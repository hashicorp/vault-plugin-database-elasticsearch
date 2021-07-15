package elasticsearch

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/ory/dockertest"
)

const (
	esVaultUser     = "vault"
	esVaultPassword = "myPa55word"
)

const (
	esInitialPassword = "PleaseChangeMe"
	esSecondPassword  = "esUserPa55word"
)

func TestIntegration_Container(t *testing.T) {
	cleanup, client, retAddress := prepareTestContainer(t)
	defer cleanup()
	verifyTestContainer(t, retAddress)
	tc := NewElasticSearchEnv(t, client, retAddress)

	env := &IntegrationTestEnv{
		Username:      esVaultUser,
		Password:      esVaultPassword,
		URL:           tc.BaseURL,
		CaCert:        filepath.Join("testdata", "certs", "rootCA.pem"),
		ClientCert:    filepath.Join("testdata", "certs", "client.pem"),
		ClientKey:     filepath.Join("testdata", "certs", "client-key.pem"),
		Elasticsearch: &Elasticsearch{},
		TestUsers:     make(map[string]dbplugin.Statements),
		TestCreds:     make(map[string]string),
		tc:            tc,
	}
	t.Run("test init", env.TestElasticsearch_Initialize)
	t.Run("test create user", env.TestElasticsearch_NewUser)
	t.Run("test delete user", env.TestElasticsearch_DeleteUser)
	t.Run("test update user", env.TestElasticsearch_UpdateUser)
}

type IntegrationTestEnv struct {
	Username, Password, URL       string
	CaCert, ClientCert, ClientKey string
	Elasticsearch                 *Elasticsearch
	TestUsers                     map[string]dbplugin.Statements
	TestCreds                     map[string]string

	tc *ElasticSearchEnv
}

func (e *IntegrationTestEnv) TestElasticsearch_Initialize(t *testing.T) {
	req := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"username":    e.Username,
			"password":    e.Password,
			"url":         e.URL,
			"ca_cert":     e.CaCert,
			"client_cert": e.ClientCert,
			"client_key":  e.ClientKey,
		},
		VerifyConnection: true,
	}
	expectedConfig := copyMap(req.Config)
	resp := dbtesting.AssertInitialize(t, e.Elasticsearch, req)

	if !reflect.DeepEqual(resp.Config, expectedConfig) {
		t.Fatalf("Actual config: %#v\nExpected config: %#v", resp.Config, expectedConfig)
	}
}

func (e *IntegrationTestEnv) TestElasticsearch_NewUser(t *testing.T) {
	statements1 := dbplugin.Statements{
		Commands: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
	}
	password1 := "initial password"
	req1 := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements1,
		Password:   password1,
	}
	resp1 := dbtesting.AssertNewUser(t, e.Elasticsearch, req1)
	if resp1.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp1.Username] = statements1
	e.TestCreds[resp1.Username] = password1

	if !e.tc.Authenticate(t, resp1.Username, password1) {
		t.Errorf("want successful authentication, got failed authentication for user:%s with password:%s", resp1.Username, password1)
	}

	statements2 := dbplugin.Statements{
		Commands: []string{`{"elasticsearch_roles": ["vault"]}`},
	}
	password2 := "second password"
	req2 := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements2,
		Password:   password2,
	}
	resp2 := dbtesting.AssertNewUser(t, e.Elasticsearch, req2)
	if resp2.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp2.Username] = statements2
	e.TestCreds[resp2.Username] = password2

	if !e.tc.Authenticate(t, resp2.Username, password2) {
		t.Errorf("want successful authentication, got failed authentication for user:%s with password:%s", resp2.Username, password2)
	}
}

func (e *IntegrationTestEnv) TestElasticsearch_DeleteUser(t *testing.T) {
	for username, statements := range e.TestUsers {
		req := dbplugin.DeleteUserRequest{
			Username:   username,
			Statements: statements,
		}
		dbtesting.AssertDeleteUser(t, e.Elasticsearch, req)
		password := e.TestCreds[username]
		if e.tc.Authenticate(t, username, password) {
			t.Errorf("want authentication failure, got successful authentication for user:%s with password:%s", username, password)
		}
	}
}

func (e *IntegrationTestEnv) TestElasticsearch_UpdateUser(t *testing.T) {
	req := dbplugin.UpdateUserRequest{
		Username: e.Username,
		Password: &dbplugin.ChangePassword{
			NewPassword: "new password",
		},
	}
	if !e.tc.Authenticate(t, e.Username, e.Password) {
		t.Errorf("want successful authentication, got failed authentication for user:%s with password:%s", e.Username, e.Password)
	}
	dbtesting.AssertUpdateUser(t, e.Elasticsearch, req)
	if e.tc.Authenticate(t, e.Username, e.Password) {
		t.Errorf("want authentication failure, got successful authentication for user:%s with password:%s", e.Username, e.Password)
	}

	if !e.tc.Authenticate(t, e.Username, "new password") {
		t.Errorf("want successful authentication, got failed authentication for user:%s with password:%s", e.Username, "new password")
	}
}

func readCertFile(t *testing.T, filename string) []byte {
	t.Helper()
	b, err := ioutil.ReadFile(filepath.Join("testdata", "certs", filename))
	if err != nil {
		t.Fatalf("Failed to read %s file: %s", filename, err)
	}
	return b
}

func prepareTestContainer(t *testing.T) (cleanup func(), client *http.Client, retAddress string) {
	t.Helper()

	certsdir, err := filepath.Abs(filepath.Join("testdata", "certs"))
	if err != nil {
		t.Fatalf("could not create an absolute path to the testdata/certs directory: %s", err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	env := []string{
		"discovery.type=single-node",
		"xpack.security.enabled=true",
		"xpack.license.self_generated.type=trial",
		"xpack.security.http.ssl.enabled=true",
		"xpack.security.http.ssl.key=/usr/share/elasticsearch/config/certificates/server-key.pem",
		"xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/certificates/server.pem",
		"xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/certificates/rootCA.pem",
		"xpack.security.http.ssl.client_authentication=required",
		"ELASTIC_PASSWORD=" + esInitialPassword,
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "docker.elastic.co/elasticsearch/elasticsearch",
		Tag:        "7.3.0",
		WorkingDir: "/usr/share/elasticsearch/",
		Mounts:     []string{certsdir + ":/usr/share/elasticsearch/config/certificates"},
		Env:        env,
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local ElasticSearch docker container: %s", err)
	}
	cleanup = func() {
		cleanupResource(t, pool, resource)
	}

	caCert := readCertFile(t, "rootCA.pem")
	clientCert := readCertFile(t, "client.pem")
	clientKey := readCertFile(t, "client-key.pem")
	tlsConf, err := tlsutil.ClientTLSConfig(caCert, clientCert, clientKey)
	if err != nil {
		cleanup()
		t.Fatalf("Could not create a client tls.Conf: %s", err)
	}

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = tlsConf
	client = cleanhttp.DefaultClient()
	client.Transport = transport

	retAddress = fmt.Sprintf("https://localhost:%s", resource.GetPort("9200/tcp"))

	if err := pool.Retry(func() error {
		var err error

		req, err := http.NewRequest(http.MethodGet, retAddress+"/_cat/health", nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth("elastic", esInitialPassword)

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = ioutil.ReadAll(resp.Body)
		return err
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to docker: %s", err)
	}
	return
}

func verifyTestContainer(t *testing.T, address string) {
	t.Helper()
	fn := func(client *http.Client) (int, error) {
		resp, err := client.Get(address + "/_cat/health")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, nil
	}
	var err error

	// verify server is using TLS
	transport := cleanhttp.DefaultTransport()
	client := cleanhttp.DefaultClient()
	client.Transport = transport
	_, err = fn(client)
	if err == nil {
		t.Fatal("want error with 'x509: certificate signed by unknown authority', got none")
	}
	if !strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
		t.Fatalf("want error with 'x509: certificate signed by unknown authority', got %s", err)
	}

	// verify client cert is required
	caCert := readCertFile(t, "rootCA.pem")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	transport.TLSClientConfig = tlsConfig

	_, err = fn(client)
	if err == nil {
		t.Fatal("want error with 'remote error: tls: bad certificate', got none")
	}
	if !strings.Contains(err.Error(), "remote error: tls: bad certificate") {
		t.Fatalf("want error with 'remote error: tls: bad certificate', got %s", err)
	}

	// verify user authenication is required
	clientCert := readCertFile(t, "client.pem")
	clientKey := readCertFile(t, "client-key.pem")
	tlsConfig, err = tlsutil.ClientTLSConfig(caCert, clientCert, clientKey)
	if err != nil {
		t.Fatalf("Could not create a client tls configuration: %s", err)
	}
	transport.TLSClientConfig = tlsConfig

	statusCode, err := fn(client)
	if err != nil {
		t.Fatalf("error type: %T, value: %#v, string: %s", err, err, err)
	}
	if http.StatusUnauthorized != statusCode {
		t.Fatalf("want status code %d, got %d", http.StatusUnauthorized, statusCode)
	}
}

func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

type ElasticSearchEnv struct {
	Username, Password string
	BaseURL            string
	Client             *http.Client
}

func NewElasticSearchEnv(t *testing.T, client *http.Client, retAddress string) *ElasticSearchEnv {
	t.Helper()

	tc := &ElasticSearchEnv{
		Username: "elastic",
		Password: esInitialPassword,
		Client:   client,
		BaseURL:  retAddress,
	}
	// Set the elastic user's password
	tc.SetPassword(t, "elastic", esSecondPassword)
	tc.Password = esSecondPassword

	if !tc.Authenticate(t, "elastic", esSecondPassword) {
		t.Fatal("failed to authenticate elastic user")
	}
	// Create a vault role and vault user in ElasticSearch
	tc.CreateVaultUser(t)
	if !tc.Authenticate(t, esVaultUser, esVaultPassword) {
		t.Fatal("failed to authenticate vault user")
	}
	return tc
}

func (e *ElasticSearchEnv) Authenticate(t *testing.T, user, password string) bool {
	t.Helper()

	endpoint := "/_xpack/security/_authenticate"
	method := http.MethodGet

	req, err := http.NewRequest(method, e.BaseURL+endpoint, nil)
	if err != nil {
		t.Fatalf("failed to create a request for authenticating a user: %s", err)
	}
	req.SetBasicAuth(user, password)

	resp, err := e.Client.Do(req)
	if err != nil {
		t.Fatalf("request to ElasticSearch failed for %s user using password %s: %s", user, password, err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %s", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	default:
		t.Fatalf("authenication error: unexpected status code: %d", resp.StatusCode)
		return false
	}
}

func (e *ElasticSearchEnv) SetPassword(t *testing.T, user, password string) {
	t.Helper()

	endpoint := "/_xpack/security/user/" + user + "/_password"
	method := http.MethodPut

	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		t.Fatalf("failed to marshal the %s user's password to %s: %s", user, password, err)
	}
	req, err := http.NewRequest(method, e.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a request for changing the %s user's password to %s: %s", user, password, err)
	}
	if err := e.do(req, nil); err != nil {
		t.Fatalf("failed to set the %s user's password to %s: %s", user, password, err)
	}
}

func (e *ElasticSearchEnv) createVaultRole(t *testing.T) {
	t.Helper()

	endpoint := "/_xpack/security/role/vault"
	method := http.MethodPost

	body, err := json.Marshal(map[string][]string{"cluster": []string{"manage_security"}})
	if err != nil {
		t.Fatalf("failed to marshal the body to create the vault role: %s", err)
	}
	req, err := http.NewRequest(method, e.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a request for creating the vault role: %s", err)
	}
	if err := e.do(req, nil); err != nil {
		t.Fatalf("failed to create the vault role: %s", err)
	}
}

func (e *ElasticSearchEnv) CreateVaultUser(t *testing.T) {
	t.Helper()
	e.createVaultRole(t)

	endpoint := "/_xpack/security/user/" + esVaultUser
	method := http.MethodPost

	type user struct {
		Name     string   `json:"full_name"`
		Password string   `json:"password"` // Passwords must be at least 6 characters long.
		Roles    []string `json:"roles"`
	}

	u := &user{
		Name:     "HashiCorp Vault",
		Password: esVaultPassword,
		Roles:    []string{"vault"},
	}

	body, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("failed to marshal the body to create the vault user: %s", err)
	}
	req, err := http.NewRequest(method, e.BaseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create a request for creating the vault user: %s", err)
	}
	if err := e.do(req, nil); err != nil {
		t.Fatalf("failed to create the vault user: %s", err)
	}
}

func (e *ElasticSearchEnv) do(req *http.Request, ret interface{}) error {
	req.SetBasicAuth(e.Username, e.Password)
	req.Header.Add("Content-Type", "application/json")

	resp, err := e.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ret == nil {
			return nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			return fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		return nil
	}

	if resp.StatusCode == 404 {
		return nil
	}
	return fmt.Errorf("%d: %s", resp.StatusCode, body)
}
