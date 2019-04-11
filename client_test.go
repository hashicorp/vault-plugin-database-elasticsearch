package elasticsearch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-plugin-database-elasticsearch/mock"
)

var ctx = context.Background()

func TestClient_CreateListGetDeleteRole(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: esAPI.Username(),
		Password: esAPI.Password(),
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	originalRole := map[string]interface{}{
		"cluster": []string{"manage_security"},
	}
	if err := client.CreateRole(ctx, "role-name", originalRole); err != nil {
		t.Fatal(err)
	}

	role, err := client.GetRole(ctx, "role-name")
	if err != nil {
		t.Fatal(err)
	}

	if fmt.Sprintf("%s", originalRole) != fmt.Sprintf("%s", role) {
		t.Fatalf("expected %s but received %s", originalRole, role)
	}

	if err := client.DeleteRole(ctx, "role-name"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CreateGetDeleteUser(t *testing.T) {
	esAPI := mock.Elasticsearch()
	ts := httptest.NewServer(http.HandlerFunc(esAPI.HandleRequests))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: esAPI.Username(),
		Password: esAPI.Password(),
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateUser(ctx, "user-name", &User{
		Password: "pa55w0rd",
		Roles:    []string{"vault"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.ChangePassword(ctx, "user-name", "newPa55w0rd"); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(ctx, "user-name"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_BadResponses(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	ts := httptest.NewServer(http.HandlerFunc(giveBadResponses))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: "fizz",
		Password: "buzz",
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRole(ctx, "200-but-body-changed"); err.Error() != "invalid character '<' looking for beginning of value; 200: <html>I switched to html!</html>" {
		t.Fatal(`expected "invalid character '<' looking for beginning of value; 200: <html>I switched to html!</html>"`)
	}
	if role, err := client.GetRole(ctx, "404-not-found"); err != nil || role != nil {
		// We shouldn't error on 404s because they are a success case.
		t.Fatal(err)
	}
	if _, err := client.GetRole(ctx, "500-mysterious-internal-server-error"); err == nil {
		t.Fatalf(`expected err`)
	}
	if _, err := client.GetRole(ctx, "503-unavailable"); err == nil {
		t.Fatal(`expected err`)
	}
}

func giveBadResponses(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_xpack/security/role/200-but-body-changed":
		w.WriteHeader(200)
		w.Write([]byte(`<html>I switched to html!</html>`))
		return

	case "/_xpack/security/role/404-not-found":
		w.WriteHeader(404)
		w.Write([]byte(`{"something": "unexpected"}`))
		return

	case "/_xpack/security/role/500-mysterious-internal-server-error":
		w.WriteHeader(500)
		w.Write([]byte(`<html>Internal Server Error</html>`))
		return

	case "/_xpack/security/role/503-unavailable":
		w.WriteHeader(503)
		w.Write([]byte(`<html>Service Unavailable</html>`))
		return
	}
}
