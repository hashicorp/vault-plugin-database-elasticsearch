package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
)

func New() (interface{}, error) {
	db := &Elasticsearch{}
	return newdbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues), nil
}

func Run(apiTLSConfig *api.TLSConfig) error {
	// TODO(tvoran): change this to use error sanitizer middleware?
	newdbplugin.Serve(NewElasticsearch(), api.VaultPluginTLSProvider(apiTLSConfig))
	return nil
}

func NewElasticsearch() *Elasticsearch {
	return &Elasticsearch{}
}

// Elasticsearch implements newdbplugin's Database interface.
type Elasticsearch struct {

	// This protects the config from races while also allowing multiple threads
	// to read the config simultaneously when it's not changing.
	mux sync.RWMutex

	// The root credential config.
	config map[string]interface{}
}

func (es *Elasticsearch) Type() (string, error) {
	return "elasticsearch", nil
}

// SecretValues is used by some error-sanitizing middleware in Vault that basically
// replaces the keys in the map with the values given so they're not leaked via
// error messages.
func (es *Elasticsearch) SecretValues() map[string]string {
	es.mux.RLock()
	defer es.mux.RUnlock()

	replacements := make(map[string]string)
	for _, secretKey := range []string{"password", "client_key"} {
		vIfc, found := es.config[secretKey]
		if !found {
			continue
		}
		secretVal, ok := vIfc.(string)
		if !ok {
			continue
		}
		// So, supposing a password of "0pen5e5ame",
		// this will cause that string to get replaced with "[password]".
		replacements[secretVal] = "[" + secretKey + "]"
	}
	return replacements
}

// Initialize is called on `$ vault write database/config/:db-name`,
// or when you do a creds call after Vault's been restarted.
func (es *Elasticsearch) Initialize(ctx context.Context, req newdbplugin.InitializeRequest) (newdbplugin.InitializeResponse, error) {

	// Validate the config to provide immediate feedback to the user.
	// Ensure required string fields are provided in the expected format.
	for _, requiredField := range []string{"username", "password", "url"} {
		raw, ok := req.Config[requiredField]
		if !ok {
			return newdbplugin.InitializeResponse{}, fmt.Errorf(`%q must be provided`, requiredField)
		}
		if _, ok := raw.(string); !ok {
			return newdbplugin.InitializeResponse{}, fmt.Errorf(`%q must be a string`, requiredField)
		}
	}

	// Ensure optional string fields are provided in the expected format.
	for _, optionalField := range []string{"ca_cert", "ca_path", "client_cert", "client_key", "tls_server_name"} {
		raw, ok := req.Config[optionalField]
		if !ok {
			continue
		}
		if _, ok = raw.(string); !ok {
			return newdbplugin.InitializeResponse{}, fmt.Errorf(`%q must be a string`, optionalField)
		}
	}

	// Check the one optional bool field is in the expected format.
	if raw, ok := req.Config["insecure"]; ok {
		if _, ok = raw.(bool); !ok {
			return newdbplugin.InitializeResponse{}, errors.New(`"insecure" must be a bool`)
		}
	}

	// Test the given config to see if we can make a client.
	client, err := buildClient(req.Config)
	if err != nil {
		return newdbplugin.InitializeResponse{}, errwrap.Wrapf("couldn't make client with inbound config: {{err}}", err)
	}

	// Optionally, test the given config to see if we can make a successful call.
	if req.VerifyConnection {
		// Whether this role is found or unfound, if we're configured correctly there will
		// be no err from the call. However, if something is misconfigured, this will yield
		// an error response, which will be described in the returned error.
		if _, err := client.GetRole(ctx, "vault-test"); err != nil {
			return newdbplugin.InitializeResponse{}, errwrap.Wrapf("client test of getting a role failed: {{err}}", err)
		}
	}

	// Everything's working, write the new config to memory and storage.
	es.mux.Lock()
	defer es.mux.Unlock()
	es.config = req.Config
	resp := newdbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

// NewUser is called on `$ vault read database/creds/:role-name`
// and it's the first time anything is touched from `$ vault write database/roles/:role-name`.
// This is likely to be the highest-throughput method for this plugin.
func (es *Elasticsearch) NewUser(ctx context.Context, req newdbplugin.NewUserRequest) (newdbplugin.NewUserResponse, error) {
	username, err := newUsername(req.UsernameConfig)
	if err != nil {
		return newdbplugin.NewUserResponse{}, errwrap.Wrapf(fmt.Sprintf("unable to generate username for %q: {{err}}", req.UsernameConfig), err)
	}

	stmt, err := newCreationStatement(req.Statements)
	if err != nil {
		return newdbplugin.NewUserResponse{}, errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	user := &User{
		Password: req.Password,
		Roles:    stmt.PreexistingRoles,
	}

	// Don't let anyone write the config while we're using it for our current client.
	es.mux.RLock()
	defer es.mux.RUnlock()

	client, err := buildClient(es.config)
	if err != nil {
		return newdbplugin.NewUserResponse{}, errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	// If the RoleToCreate map has been populated with any data, we have one role to create.
	// There can either be one RoleToCreate and no PreexistingRoles, or >= 1 PreexistingRoles
	// and no RoleToCreate. They're mutually exclusive.
	if len(stmt.RoleToCreate) > 0 {
		// We'll simply name the role the same thing as the username, making it easy to tie back to this user.
		if err := client.CreateRole(ctx, username, stmt.RoleToCreate); err != nil {
			return newdbplugin.NewUserResponse{}, errwrap.Wrapf(fmt.Sprintf("unable to create role name %s, role definition %q: {{err}}", username, stmt.RoleToCreate), err)
		}
		user.Roles = []string{username}
	}
	if err := client.CreateUser(ctx, username, user); err != nil {
		return newdbplugin.NewUserResponse{}, errwrap.Wrapf(fmt.Sprintf("unable to create user name %s, user %q: {{err}}", username, user), err)
	}
	resp := newdbplugin.NewUserResponse{
		Username: username,
	}
	return resp, nil
}

// copied from the mongodb PR
func newUsername(config newdbplugin.UsernameMetadata) (string, error) {
	displayName := trunc(config.DisplayName, 15)
	roleName := trunc(config.RoleName, 15)

	userUUID, err := credsutil.RandomAlphaNumeric(20, false)
	if err != nil {
		return "", err
	}

	now := fmt.Sprint(time.Now().Unix())

	parts := []string{
		"v",
		displayName,
		roleName,
		userUUID,
		now,
	}
	username := joinNonEmpty("-", parts...)
	username = trunc(username, 100)

	return username, nil
}

// copied from the mongodb PR
func trunc(str string, l int) string {
	if len(str) < l {
		return str
	}
	return str[:l]
}

// copied from the mongodb PR
func joinNonEmpty(sep string, vals ...string) string {
	if sep == "" {
		return strings.Join(vals, sep)
	}
	switch len(vals) {
	case 0:
		return ""
	case 1:
		return vals[0]
	}
	builder := &strings.Builder{}
	for _, val := range vals {
		if val == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString(sep)
		}
		builder.WriteString(val)
	}
	return builder.String()
}

// copied from the mongodb PR
func removeEmpty(input []string) []string {
	output := []string{}
	for _, val := range input {
		if val != "" {
			output = append(output, val)
		}
	}
	return output
}

// DeleteUser is used to delete users from elasticsearch
func (es *Elasticsearch) DeleteUser(ctx context.Context, req newdbplugin.DeleteUserRequest) (newdbplugin.DeleteUserResponse, error) {
	stmt, err := newCreationStatement(req.Statements)
	if err != nil {
		return newdbplugin.DeleteUserResponse{}, errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	// Don't let anyone write the config while we're using it for our current client.
	es.mux.RLock()
	defer es.mux.RUnlock()

	client, err := buildClient(es.config)
	if err != nil {
		return newdbplugin.DeleteUserResponse{}, errwrap.Wrapf("unable to get client: {{err}}", err)
	}

	var errs error
	if len(stmt.RoleToCreate) > 0 {
		// If the role already doesn't exist because it was successfully deleted on a previous
		// attempt to run this code, there will be no error, so it's harmless to try.
		if err := client.DeleteRole(ctx, req.Username); err != nil {
			errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to delete role name %s: {{err}}", req.Username), err))
		}
	}
	// Same with the user. If it was already deleted on a previous attempt, there won't be an
	// error.
	if err := client.DeleteUser(ctx, req.Username); err != nil {
		errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to create user name %s: {{err}}", req.Username), err))
	}
	return newdbplugin.DeleteUserResponse{}, errs
}

// UpdateUser doesn't require any statements from the user because it's not configurable in any
// way. We simply generate a new password and hit a pre-defined Elasticsearch REST API to rotate them.
func (es *Elasticsearch) UpdateUser(ctx context.Context, req newdbplugin.UpdateUserRequest) (newdbplugin.UpdateUserResponse, error) {
	// newPassword, err := es.credentialProducer.GeneratePassword()
	// if err != nil {
	// 	return nil, errwrap.Wrapf("unable to generate root password: {{err}}", err)
	// }

	// Don't let anyone read or write the config while we're in the process of rotating the password.
	es.mux.Lock()
	defer es.mux.Unlock()

	client, err := buildClient(es.config)
	if err != nil {
		return newdbplugin.UpdateUserResponse{}, fmt.Errorf("unable to get client: %w", err)
	}

	if req.Password != nil {
		if err := client.ChangePassword(ctx, es.config["username"].(string), req.Password.NewPassword); err != nil {
			return newdbplugin.UpdateUserResponse{}, fmt.Errorf("unable to change password: %w", err)
		}

	}

	return newdbplugin.UpdateUserResponse{}, nil
}

func (es *Elasticsearch) Close() error {
	// NOOP, nothing to close.
	return nil
}

func newCreationStatement(statements newdbplugin.Statements) (*creationStatement, error) {
	if len(statements.Commands) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}
	stmt := &creationStatement{}
	if err := json.Unmarshal([]byte(statements.Commands[0]), stmt); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to unmarshal %s: {{err}}", []byte(statements.Commands[0])), err)
	}
	if len(stmt.PreexistingRoles) > 0 && len(stmt.RoleToCreate) > 0 {
		return nil, errors.New(`"elasticsearch_roles" and "elasticsearch_role_definition" are mutually exclusive`)
	}
	return stmt, nil
}

type creationStatement struct {
	PreexistingRoles []string               `json:"elasticsearch_roles"`
	RoleToCreate     map[string]interface{} `json:"elasticsearch_role_definition"`
}

// buildClient is a helper method for building a client from the present config,
// which is done often.
func buildClient(config map[string]interface{}) (*Client, error) {

	// We can presume these required fields are provided by strings
	// because they're validated in Init.
	clientConfig := &ClientConfig{
		Username: config["username"].(string),
		Password: config["password"].(string),
		BaseURL:  config["url"].(string),
	}

	hasTLSConf := false
	tlsConf := &TLSConfig{}

	// We can presume that if these are provided, they're in the expected format
	// because they're also validated in Init.
	if raw, ok := config["ca_cert"]; ok {
		tlsConf.CACert = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["ca_path"]; ok {
		tlsConf.CAPath = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["client_cert"]; ok {
		tlsConf.ClientCert = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["client_key"]; ok {
		tlsConf.ClientKey = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["tls_server_name"]; ok {
		tlsConf.TLSServerName = raw.(string)
		hasTLSConf = true
	}
	if raw, ok := config["insecure"]; ok {
		tlsConf.Insecure = raw.(bool)
		hasTLSConf = true
	}

	// We should only fulfill the clientConfig's TLSConfig pointer if we actually
	// want the client to use TLS.
	if hasTLSConf {
		clientConfig.TLSConfig = tlsConf
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}
