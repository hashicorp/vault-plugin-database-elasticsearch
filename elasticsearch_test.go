package elasticsearch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-plugin-database-elasticsearch/mock"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
)

func TestElasticsearch(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	env := &UnitTestEnv{
		Username:      esAPI.Username(),
		Password:      esAPI.Password(),
		URL:           ts.URL,
		Elasticsearch: NewElasticsearch(),
		TestUsers:     make(map[string]newdbplugin.Statements),
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

	TestUsers map[string]newdbplugin.Statements
}

func (e *UnitTestEnv) TestElasticsearch_Type(t *testing.T) {
	if tp, err := e.Elasticsearch.Type(); err != nil {
		t.Fatal(err)
	} else if tp != "elasticsearch" {
		t.Fatalf("expected elasticsearch but received %s", tp)
	}
}

func (e *UnitTestEnv) TestElasticsearch_Initialize(t *testing.T) {
	req := newdbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"username": e.Username,
			"password": e.Password,
			"url":      e.URL,
		},
		VerifyConnection: true,
	}
	resp, err := e.Elasticsearch.Initialize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Config) != len(req.Config) {
		t.Fatalf("expected %s, received %s", req.Config, resp.Config)
	}
	for k, v := range req.Config {
		if resp.Config[k] != v {
			t.Fatalf("for %s, expected %s but received %s", k, v, resp.Config[k])
		}
	}
}

func (e *UnitTestEnv) TestElasticsearch_NewUser(t *testing.T) {
	statements1 := newdbplugin.Statements{
		Commands: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
	}
	req1 := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements1,
	}
	resp1, err := e.Elasticsearch.NewUser(context.Background(), req1)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp1.Username] = statements1

	statements2 := newdbplugin.Statements{
		Commands: []string{`{"elasticsearch_roles": ["vault"]}`},
	}
	req2 := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "display-name",
			RoleName:    "role-name",
		},
		Statements: statements2,
	}
	resp2, err := e.Elasticsearch.NewUser(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Username == "" {
		t.Fatal("expected username")
	}
	e.TestUsers[resp2.Username] = statements2
}

func (e *UnitTestEnv) TestElasticsearch_DeleteUser(t *testing.T) {
	for username, statements := range e.TestUsers {
		req := newdbplugin.DeleteUserRequest{
			Username:   username,
			Statements: statements,
		}
		if _, err := e.Elasticsearch.DeleteUser(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *UnitTestEnv) TestElasticsearch_UpdateUser(t *testing.T) {
	req := newdbplugin.UpdateUserRequest{
		Username: e.Username,
		Password: &newdbplugin.ChangePassword{
			NewPassword: "new password",
		},
	}
	// originalConfig := map[string]interface{}{
	// 	"username": e.Username,
	// 	"password": e.Password,
	// 	"url":      e.URL,
	// }
	_, err := e.Elasticsearch.UpdateUser(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// if len(originalConfig) != len(configToStore) {
	// 	t.Fatalf("expected %s, received %s", originalConfig, configToStore)
	// }
	// for k, v := range originalConfig {
	// 	if k == "password" {
	// 		if configToStore[k] == v {
	// 			t.Fatal("password should have changed")
	// 		}
	// 		continue
	// 	}
	// 	if configToStore[k] != v {
	// 		t.Fatalf("for %s, expected %s but received %s", k, v, configToStore[k])
	// 	}
	// }
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
