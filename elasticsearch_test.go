package elasticsearch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-database-elasticsearch/mock"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
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
		TestUsers:     make(map[string]dbplugin.Statements),
	}

	t.Run("test type", env.TestElasticsearch_Type)
	t.Run("test init", env.TestElasticsearch_Init)
	t.Run("test initialize", env.TestElasticsearch_Initialize)
	t.Run("test create user", env.TestElasticsearch_CreateUser)
	t.Run("test revoke user", env.TestElasticsearch_RevokeUser)
	t.Run("test rotate root creds", env.TestElasticsearch_RotateRootCredentials)
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

func (e *UnitTestEnv) TestElasticsearch_Init(t *testing.T) {
	config := map[string]interface{}{
		"username": e.Username,
		"password": e.Password,
		"url":      e.URL,
	}
	configToStore, err := e.Elasticsearch.Init(context.Background(), config, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(configToStore) != len(config) {
		t.Fatalf("expected %s, received %s", config, configToStore)
	}
	for k, v := range config {
		if configToStore[k] != v {
			t.Fatalf("for %s, expected %s but received %s", k, v, configToStore[k])
		}
	}
}

func (e *UnitTestEnv) TestElasticsearch_Initialize(t *testing.T) {
	config := map[string]interface{}{
		"username": e.Username,
		"password": e.Password,
		"url":      e.URL,
	}
	if err := e.Elasticsearch.Initialize(context.Background(), config, true); err != nil {
		t.Fatal(err)
	}
}

func (e *UnitTestEnv) TestElasticsearch_CreateUser(t *testing.T) {
	statements1 := dbplugin.Statements{
		Creation: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
	}
	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "display-name",
		RoleName:    "role-name",
	}
	username1, password1, err := e.Elasticsearch.CreateUser(context.Background(), statements1, usernameConfig, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if username1 == "" {
		t.Fatal("expected username")
	}
	if password1 == "" {
		t.Fatal("expected password")
	}
	e.TestUsers[username1] = statements1

	statements2 := dbplugin.Statements{
		Creation: []string{`{"elasticsearch_roles": ["vault"]}`},
	}
	username2, password2, err := e.Elasticsearch.CreateUser(context.Background(), statements2, usernameConfig, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if username2 == "" {
		t.Fatal("expected username")
	}
	if password2 == "" {
		t.Fatal("expected password")
	}
	e.TestUsers[username2] = statements2
}

func (e *UnitTestEnv) TestElasticsearch_RevokeUser(t *testing.T) {
	for username, statements := range e.TestUsers {
		if err := e.Elasticsearch.RevokeUser(context.Background(), statements, username); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *UnitTestEnv) TestElasticsearch_RotateRootCredentials(t *testing.T) {
	originalConfig := map[string]interface{}{
		"username": e.Username,
		"password": e.Password,
		"url":      e.URL,
	}
	configToStore, err := e.Elasticsearch.RotateRootCredentials(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(originalConfig) != len(configToStore) {
		t.Fatalf("expected %s, received %s", originalConfig, configToStore)
	}
	for k, v := range originalConfig {
		if k == "password" {
			if configToStore[k] == v {
				t.Fatal("password should have changed")
			}
			continue
		}
		if configToStore[k] != v {
			t.Fatalf("for %s, expected %s but received %s", k, v, configToStore[k])
		}
	}
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
	if val["buzz"] != nil {
		t.Fatal(`buzz isn't secret and shouldn't be in the map`)
	}
	if val["dont-show-me!"] != "[password]" {
		t.Fatalf("expected %q but received %q", "[password]", val["dont-show-me!"])
	}
	if val["dont-show-me-either!"] != "[client_key]" {
		t.Fatalf("expected %q but received %q", "[client_key]", val["dont-show-me-either!"])
	}
}
