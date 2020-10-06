package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault-plugin-database-elasticsearch/mock"
)

/*
These tests are end-to-end, running from Vault to the real plugin. To run these tests, first make
a binary of the present code:

$ make dev

Then start Vault with commands like:

$ export VAULT_API_ADDR=http://localhost:8200
$ vault server -dev \
	-dev-root-token-id=root \
	-dev-plugin-dir=$GOPATH/src/github.com/hashicorp/vault-plugin-database-elasticsearch/bin

The last flag automatically adds this plugin to the plugin catalog. Then set the following variables:

$ export VAULT_ACC=1
$ export VAULT_ADDR=http://localhost:8200
$ export VAULT_TOKEN=root

At that point, you'll be able to successfully run the tests.

If you don't provide the ES_URL for an instance of Elasticsearch with the security X-Pack enabled
(which requires a license), the tests will use a mocked version of Elasticsearch based on the
ES security API that was present in ES version 6.6.1. However, if you _would_ like to run against
it, Please see README.md and carefully ensure you've set it up properly. Then set the following
variables

$ export ES_URL=http://localhost:9200
$ export ES_USERNAME=vault
$ export ES_PASSWORD=myPa55word
$ export CA_CERT=/usr/share/ca-certificates/extra/elastic-stack-ca.crt.pem
$ export CLIENT_CERT=$ES_HOME/config/certs/elastic-certificates.crt.pem
$ export CLIENT_KEY=$ES_HOME/config/certs/elastic-certificates.key.pem

Also create a 'vault' role for Test_ExternallyDefinedRole, ex:

$ curl \
    -k -X POST \
    -H "Content-Type: application/json" \
    -d '{"cluster": ["manage_security"]}' \
    https://elastic:$ES_PASSWORD@localhost:9200/_xpack/security/role/vault

*/
func Test_Acceptance(t *testing.T) {

	if os.Getenv("VAULT_ACC") != "1" {
		t.SkipNow()
	}

	env := &Environment{
		VaultAddr:  os.Getenv("VAULT_ADDR"),
		VaultToken: os.Getenv("VAULT_TOKEN"),
		Config: map[string]interface{}{
			"plugin_name":   "vault-plugin-database-elasticsearch",
			"allowed_roles": "internally-defined-role,externally-defined-role",
		},
		Leases: make(map[string]string),
	}

	if os.Getenv("ES_URL") != "" {
		log.Printf("running tests against the Elasticsearch url provided")

		env.Config["username"] = os.Getenv("ES_USERNAME")
		env.Config["password"] = os.Getenv("ES_PASSWORD")
		env.Config["url"] = os.Getenv("ES_URL")

		if os.Getenv("CA_CERT") != "" {
			env.Config["ca_cert"] = os.Getenv("CA_CERT")
		}
		if os.Getenv("CLIENT_CERT") != "" {
			env.Config["client_cert"] = os.Getenv("CLIENT_CERT")
		}
		if os.Getenv("CLIENT_KEY") != "" {
			env.Config["client_key"] = os.Getenv("CLIENT_KEY")
		}
	} else {
		log.Print("running tests against mocked Elasticsearch")

		esAPI := mock.Elasticsearch()
		ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
		defer ts.Close()

		env.Config["username"] = esAPI.Username()
		env.Config["password"] = esAPI.Password()
		env.Config["url"] = ts.URL
	}

	log.Print("enabling database secrets engine")
	resp, err := env.doVaultReq(http.MethodPost, "/v1/sys/mounts/database", map[string]interface{}{
		"type": "database",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	t.Run("write a config", env.Test_WriteConfig)
	t.Run("test internally defined roles", env.Test_InternallyDefinedRole)
	t.Run("test externally defined roles", env.Test_ExternallyDefinedRole)
	t.Run("test credential renewal", env.Test_RenewCredentials)
	t.Run("test credential revocation", env.Test_RevokeCredentials)
	t.Run("test root credential rotation", env.Test_RotateRootCredentials)
	t.Run("check raciness", env.Test_Raciness)
}

type Environment struct {
	VaultAddr, VaultToken string
	Config                map[string]interface{}
	Leases                map[string]string // rolename to lease ID
}

func (e *Environment) Test_WriteConfig(t *testing.T) {
	// Write the config.
	writeResp, err := e.doVaultReq(http.MethodPost, "/v1/database/config/my-elasticsearch-database", e.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer writeResp.Body.Close()
	if writeResp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(writeResp.Body)
		t.Fatalf("expected 200 but received %d: %s", writeResp.StatusCode, string(body))
	}

	// Read it and make sure it's holding expected values.
	readResp, err := e.doVaultReq(http.MethodGet, "/v1/database/config/my-elasticsearch-database", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer readResp.Body.Close()
	if readResp.StatusCode != 200 {
		t.Fatalf("expected 200 but received %d", readResp.StatusCode)
	}
	readRespBody := make(map[string]interface{})
	if err := json.NewDecoder(readResp.Body).Decode(&readRespBody); err != nil {
		t.Fatal(err)
	}
	respData := readRespBody["data"].(map[string]interface{})
	connectionDetails := respData["connection_details"].(map[string]interface{})

	if e.Config["plugin_name"] != respData["plugin_name"] {
		t.Fatalf(`expected "plugin_name" %s but received %s`, e.Config["plugin_name"], respData["plugin_name"])
	}
	if fmt.Sprintf("[%s]", e.Config["allowed_roles"]) != strings.Replace(fmt.Sprintf("%s", respData["allowed_roles"]), " ", ",", -1) {
		t.Fatalf(`expected "allowed_roles" %s but received %s`, e.Config["allowed_roles"], respData["allowed_roles"])
	}
	if e.Config["url"] != connectionDetails["url"] {
		t.Fatalf(`expected "url" %s but received %s`, e.Config["url"], connectionDetails["url"])
	}
	if e.Config["username"] != connectionDetails["username"] {
		t.Fatalf(`expected "username" %s but received %s`, e.Config["username"], connectionDetails["username"])
	}
	if connectionDetails["password"] != nil {
		t.Fatal("password should not be returned!!!!")
	}
}

func (e *Environment) Test_InternallyDefinedRole(t *testing.T) {
	// Write the role.
	writeResp, err := e.doVaultReq(http.MethodPost, "/v1/database/roles/internally-defined-role", map[string]interface{}{
		"db_name":             "my-elasticsearch-database",
		"creation_statements": `{"elasticsearch_role_definition": {"cluster": ["manage_security"]}}`,
		"default_ttl":         "1h",
		"max_ttl":             "24h",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writeResp.Body.Close()
	if writeResp.StatusCode != 204 {
		t.Fatalf("expected 204 but received %d", writeResp.StatusCode)
	}

	// Read it and ensure it's holding expected values.
	readResp, err := e.doVaultReq(http.MethodGet, "/v1/database/roles/internally-defined-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer readResp.Body.Close()
	if readResp.StatusCode != 200 {
		t.Fatalf("expected 200 but received %d", readResp.StatusCode)
	}
	readRespBody := make(map[string]interface{})
	if err := json.NewDecoder(readResp.Body).Decode(&readRespBody); err != nil {
		t.Fatal(err)
	}
	respData := readRespBody["data"].(map[string]interface{})
	if stmts, ok := respData["creation_statements"]; !ok {
		t.Fatal("expected creation_statements but they weren't returned")
	} else if len(stmts.([]interface{})) != 1 {
		t.Fatalf("expected 1 creation_statements but received %s", stmts)
	} else if fmt.Sprintf("%s", stmts.([]interface{})[0]) != `{"elasticsearch_role_definition": {"cluster": ["manage_security"]}}` {
		t.Fatalf("received unexpected statement: %s", stmts.([]interface{})[0])
	}
	if respData["default_ttl"].(float64) != 3600 {
		t.Fatalf("default_ttl should be 3600 seconds")
	}
	if respData["max_ttl"].(float64) != 86400 {
		t.Fatalf("max_ttl should be 3600 seconds")
	}

	// Read creds and ensure they look correct.
	credsResp, err := e.doVaultReq(http.MethodGet, "/v1/database/creds/internally-defined-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer credsResp.Body.Close()
	if credsResp.StatusCode != 200 {
		t.Fatalf("expected 200 but received %d", credsResp.StatusCode)
	}

	credsRespBody := make(map[string]interface{})

	if err := json.NewDecoder(credsResp.Body).Decode(&credsRespBody); err != nil {
		t.Fatal(err)
	}
	leaseID := credsRespBody["lease_id"].(string)
	if leaseID == "" {
		t.Fatal("expected lease_id")
	}
	e.Leases["internally-defined-role"] = leaseID
	if !credsRespBody["renewable"].(bool) {
		t.Fatal("expected renewable to be true")
	}
	if credsRespBody["lease_duration"].(float64) != 3600 {
		t.Fatal("expected lease to last for 3600 seconds")
	}

	credData := credsRespBody["data"].(map[string]interface{})
	username := credData["username"].(string)
	if username == "" {
		t.Fatalf("%s didn't return a username", credData)
	}
	password := credData["password"].(string)
	if password == "" {
		t.Fatalf("%s didn't return a password", credData)
	}

	// Test the new credentials by deleting this user.
	configCopy := copyMap(e.Config)
	configCopy["username"] = username
	configCopy["password"] = password
	userClient, err := buildClient(configCopy)
	if err != nil {
		t.Fatal(err)
	}
	if err := userClient.DeleteUser(context.Background(), username); err != nil {
		t.Fatal(err)
	}
	// Delete the role using the root creds
	client, err := buildClient(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteRole(context.Background(), username); err != nil {
		t.Fatal(err)
	}
}

func (e *Environment) Test_ExternallyDefinedRole(t *testing.T) {
	// Write the role.
	writeResp, err := e.doVaultReq(http.MethodPost, "/v1/database/roles/externally-defined-role", map[string]interface{}{
		"db_name":             "my-elasticsearch-database",
		"creation_statements": `{"elasticsearch_roles": ["vault"]}`,
		"default_ttl":         "1h",
		"max_ttl":             "24h",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writeResp.Body.Close()
	if writeResp.StatusCode != 204 {
		t.Fatalf("expected 204 but received %d", writeResp.StatusCode)
	}

	// Read it and ensure it's holding expected values.
	readResp, err := e.doVaultReq(http.MethodGet, "/v1/database/roles/externally-defined-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer readResp.Body.Close()
	if readResp.StatusCode != 200 {
		t.Fatalf("expected 200 but received %d", readResp.StatusCode)
	}
	readRespBody := make(map[string]interface{})
	if err := json.NewDecoder(readResp.Body).Decode(&readRespBody); err != nil {
		t.Fatal(err)
	}
	respData := readRespBody["data"].(map[string]interface{})
	if stmts, ok := respData["creation_statements"]; !ok {
		t.Fatal("expected creation_statements but they weren't returned")
	} else if len(stmts.([]interface{})) != 1 {
		t.Fatalf("expected 1 creation_statements but received %s", stmts)
	} else if fmt.Sprintf("%s", stmts.([]interface{})[0]) != `{"elasticsearch_roles": ["vault"]}` {
		t.Fatalf("received unexpected statement: %s", stmts.([]interface{})[0])
	}
	if respData["default_ttl"].(float64) != 3600 {
		t.Fatalf("default_ttl should be 3600 seconds")
	}
	if respData["max_ttl"].(float64) != 86400 {
		t.Fatalf("max_ttl should be 3600 seconds")
	}

	// Read creds and ensure they look correct.
	credsResp, err := e.doVaultReq(http.MethodGet, "/v1/database/creds/externally-defined-role", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer credsResp.Body.Close()
	if credsResp.StatusCode != 200 {
		t.Fatalf("expected 200 but received %d", credsResp.StatusCode)
	}
	credsRespBody := make(map[string]interface{})
	if err := json.NewDecoder(credsResp.Body).Decode(&credsRespBody); err != nil {
		t.Fatal(err)
	}
	leaseID := credsRespBody["lease_id"].(string)
	if leaseID == "" {
		t.Fatal("expected lease_id")
	}
	e.Leases["externally-defined-role"] = leaseID
	if !credsRespBody["renewable"].(bool) {
		t.Fatal("expected renewable to be true")
	}
	if credsRespBody["lease_duration"].(float64) != 3600 {
		t.Fatal("expected lease to last for 3600 seconds")
	}

	credData := credsRespBody["data"].(map[string]interface{})
	username := credData["username"].(string)
	if username == "" {
		t.Fatalf("%s didn't return a username", credData)
	}
	password := credData["password"].(string)
	if password == "" {
		t.Fatalf("%s didn't return a password", credData)
	}

	// Test the new credentials by deleting this user.
	configCopy := copyMap(e.Config)
	configCopy["username"] = username
	configCopy["password"] = password
	client, err := buildClient(configCopy)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(context.Background(), username); err != nil {
		t.Fatal(err)
	}
}

func (e *Environment) Test_RenewCredentials(t *testing.T) {
	firstRenewal, err := e.doVaultReq(http.MethodPost, "/v1/sys/leases/renew", map[string]interface{}{
		"lease_id":  e.Leases["internally-defined-role"],
		"increment": 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer firstRenewal.Body.Close()

	result := make(map[string]interface{})
	if err := json.NewDecoder(firstRenewal.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if firstRenewal.StatusCode != 200 {
		t.Fatalf("%d: %s", firstRenewal.StatusCode, result)
	}
	if result["lease_duration"].(float64) != 100 {
		t.Fatal("expected lease_duration of 100")
	}
	if result["lease_id"] != e.Leases["internally-defined-role"] {
		t.Fatalf("expected lease_id %s but received %s", e.Leases["internally-defined-role"], result["lease_id"])
	}
	if !result["renewable"].(bool) {
		t.Fatal("expected renewable to be true")
	}

	secondRenewal, err := e.doVaultReq(http.MethodPost, "/v1/sys/leases/renew", map[string]interface{}{
		"lease_id":  e.Leases["externally-defined-role"],
		"increment": 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secondRenewal.Body.Close()

	result = make(map[string]interface{})
	if err := json.NewDecoder(secondRenewal.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["lease_duration"].(float64) != 100 {
		t.Fatal("expected lease_duration of 100")
	}
	if result["lease_id"] != e.Leases["externally-defined-role"] {
		t.Fatalf("expected lease_id %s but received %s", e.Leases["externally-defined-role"], result["lease_id"])
	}
	if !result["renewable"].(bool) {
		t.Fatal("expected renewable to be true")
	}
}

func (e *Environment) Test_RevokeCredentials(t *testing.T) {
	firstRevocation, err := e.doVaultReq(http.MethodPut, "/v1/sys/leases/revoke", map[string]interface{}{
		"lease_id": e.Leases["internally-defined-role"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer firstRevocation.Body.Close()
	if firstRevocation.StatusCode != 204 {
		body, _ := ioutil.ReadAll(firstRevocation.Body)
		t.Fatalf("expected 204 but received %d: %s", firstRevocation.StatusCode, string(body))
	}

	secondRevocation, err := e.doVaultReq(http.MethodPut, "/v1/sys/leases/revoke", map[string]interface{}{
		"lease_id": e.Leases["externally-defined-role"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secondRevocation.Body.Close()
	if secondRevocation.StatusCode != 204 {
		t.Fatalf("expected 204 but received %d", secondRevocation.StatusCode)
	}
}

func (e *Environment) Test_RotateRootCredentials(t *testing.T) {
	// This test is included for manual local testing, but is otherwise generally disabled.
	t.SkipNow()

	resp, err := e.doVaultReq(http.MethodPost, "/v1/database/rotate-root/my-elasticsearch-database", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 but received %d", resp.StatusCode)
	}
}

func (e *Environment) Test_Raciness(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	// Write and read the config as quickly as possible.
	start := make(chan struct{})
	go func() {
		<-start
		for i := 0; i < 500; i++ {
			resp, err := e.doVaultReq(http.MethodPost, "/v1/database/config/my-elasticsearch-database", e.Config)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
	}()
	go func() {
		<-start
		for i := 0; i < 500; i++ {
			resp, err := e.doVaultReq(http.MethodGet, "/v1/database/config/my-elasticsearch-database", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
	}()
	go func() {
		<-start
		for i := 0; i < 500; i++ {
			resp, err := e.doVaultReq(http.MethodPost, "/v1/database/rotate-root/my-elasticsearch-database", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
	}()
	close(start)
	time.Sleep(time.Second * 10)
}

func (e *Environment) doVaultReq(method, endpoint string, body map[string]interface{}) (resp *http.Response, err error) {
	var req *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, e.VaultAddr+endpoint, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(method, e.VaultAddr+endpoint, nil)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("X-Vault-Token", e.VaultToken)
	return cleanhttp.DefaultClient().Do(req)
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	mCopy := make(map[string]interface{})
	for k, v := range m {
		mCopy[k] = v
	}
	return mCopy
}
