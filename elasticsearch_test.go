package elasticsearch

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-database-elasticsearch/mock"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/stretchr/testify/require"
)

func TestElasticsearch(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	env := &UnitTestEnv{
		Username:      esAPI.Username(),
		Password:      esAPI.Password(),
		URL:           ts.URL,
		Elasticsearch: &Elasticsearch{},
		TestUsers:     make(map[string]dbplugin.Statements),
	}

	t.Run("test type", env.TestElasticsearch_Type)
	t.Run("test initialize", env.TestElasticsearch_Initialize)
	t.Run("test new user", env.TestElasticsearch_NewUser)
	t.Run("test delete user", env.TestElasticsearch_DeleteUser)
	t.Run("test update user", env.TestElasticsearch_UpdateUser)
}

type UnitTestEnv struct {
	Username, Password, URL string
	Elasticsearch           *Elasticsearch

	TestUsers map[string]dbplugin.Statements
}

func (e *UnitTestEnv) TestElasticsearch_Type(t *testing.T) {
	if tp, err := e.Elasticsearch.Type(); err != nil {
		t.Fatal(err)
	} else if tp != "elasticsearch" {
		t.Fatalf("expected elasticsearch but received %s", tp)
	}
}

func (e *UnitTestEnv) TestElasticsearch_Initialize(t *testing.T) {
	req := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"username": e.Username,
			"password": e.Password,
			"url":      e.URL,
		},
		VerifyConnection: true,
	}
	expectedConfig := copyMap(req.Config)
	resp := dbtesting.AssertInitialize(t, e.Elasticsearch, req)

	if !reflect.DeepEqual(resp.Config, expectedConfig) {
		t.Fatalf("Actual config: %#v\nExpected config: %#v", resp.Config, expectedConfig)
	}
}

func (e *UnitTestEnv) TestElasticsearch_NewUser(t *testing.T) {
	statements1 := dbplugin.Statements{
		Commands: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
	}
	req1 := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements1,
	}
	resp1 := dbtesting.AssertNewUser(t, e.Elasticsearch, req1)
	if resp1.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp1.Username] = statements1

	statements2 := dbplugin.Statements{
		Commands: []string{`{"elasticsearch_roles": ["vault"]}`},
	}
	req2 := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements2,
	}
	resp2 := dbtesting.AssertNewUser(t, e.Elasticsearch, req2)
	if resp2.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp2.Username] = statements2
}

func (e *UnitTestEnv) TestElasticsearch_DeleteUser(t *testing.T) {
	for username, statements := range e.TestUsers {
		req := dbplugin.DeleteUserRequest{
			Username:   username,
			Statements: statements,
		}
		dbtesting.AssertDeleteUser(t, e.Elasticsearch, req)
	}
}

func (e *UnitTestEnv) TestElasticsearch_UpdateUser(t *testing.T) {
	req := dbplugin.UpdateUserRequest{
		Username: e.Username,
		Password: &dbplugin.ChangePassword{
			NewPassword: "new password",
		},
	}
	dbtesting.AssertUpdateUser(t, e.Elasticsearch, req)
}

func TestElasticsearch_SecretValues(t *testing.T) {
	es := &Elasticsearch{
		config: map[string]interface{}{
			"fizz":       "buzz",
			"password":   "dont-show-me!",
			"client_key": "dont-show-me-either!",
		},
	}
	val := es.SecretValues()
	if val["buzz"] != "" {
		t.Fatal(`buzz isn't secret and shouldn't be in the map`)
	}
	if val["dont-show-me!"] != "[password]" {
		t.Fatalf("expected %q but received %q", "[password]", val["dont-show-me!"])
	}
	if val["dont-show-me-either!"] != "[client_key]" {
		t.Fatalf("expected %q but received %q", "[client_key]", val["dont-show-me-either!"])
	}
}

func TestElasticsearch_DefaultUsernameTemplate(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	db := &Elasticsearch{}
	req := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"username": esAPI.Username(),
			"password": esAPI.Password(),
			"url":      ts.URL,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, req)

	password := "0ZsueAP-dqCNGZo35M0n"
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: dbplugin.Statements{
			Commands: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
		},
		Password:   password,
		Expiration: time.Now().Add(1 * time.Minute),
	}
	resp := dbtesting.AssertNewUser(t, db, newUserReq)

	require.Regexp(t, `^v-display-name-role-name-[a-zA-Z0-9]{20}-[0-9]{10}$`, resp.Username)
}

func TestElasticsearch_CustomUsernameTemplate(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	db := &Elasticsearch{}
	req := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"username":          esAPI.Username(),
			"password":          esAPI.Password(),
			"url":               ts.URL,
			"username_template": "{{.DisplayName}}-{{random 10}}",
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, req)

	password := "0ZsueAP-dqCNGZo35M0n"
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: dbplugin.Statements{
			Commands: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
		},
		Password:   password,
		Expiration: time.Now().Add(1 * time.Minute),
	}
	resp := dbtesting.AssertNewUser(t, db, newUserReq)

	if resp.Username == "" {
		t.Fatalf("Missing username")
	}

	require.Regexp(t, `^display-name-[a-zA-Z0-9]{10}$`, resp.Username)
}
