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
		"cluster": []string{"manage_security", "monitor"},
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
		t.Fatalf(`expected "invalid character '<' looking for beginning of value; 200: <html>I switched to html!</html>": %s`, err)
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
	case "/":
		w.WriteHeader(200)
		w.Write([]byte(`{
			"version" : {
			  "number" : "7.0.0"
			}
		}`))
		return

	case "/_xpack/security/role/200-but-body-changed":
	case "/_security/role/200-but-body-changed":
		w.WriteHeader(200)
		w.Write([]byte(`<html>I switched to html!</html>`))
		return

	case "/_xpack/security/role/404-not-found":
	case "/_security/role/404-not-found":
		w.WriteHeader(404)
		w.Write([]byte(`{"something": "unexpected"}`))
		return

	case "/_xpack/security/role/500-mysterious-internal-server-error":
	case "/_security/role/500-mysterious-internal-server-error":
		w.WriteHeader(500)
		w.Write([]byte(`<html>Internal Server Error</html>`))
		return

	case "/_xpack/security/role/503-unavailable":
	case "/_security/role/503-unavailable":
		w.WriteHeader(503)
		w.Write([]byte(`<html>Service Unavailable</html>`))
		return
	}
}

func Test_setSecurityPath(t *testing.T) {

	type testCase struct {
		esInfoHandler http.HandlerFunc
		expectedPath  string
		wantErr       bool
	}
	tests := map[string]testCase{
		"version 7": {
			expectedPath: "/_security",
			esInfoHandler: func(w http.ResponseWriter, r *http.Request) {
				esBaseURLEndpoint(w, r, "7.0.0")
			},
		},
		"version 6": {
			expectedPath: "/_xpack/security",
			esInfoHandler: func(w http.ResponseWriter, r *http.Request) {
				esBaseURLEndpoint(w, r, "6.8.9")
			},
		},
		"bad version": {
			wantErr: true,
			esInfoHandler: func(w http.ResponseWriter, r *http.Request) {
				esBaseURLEndpoint(w, r, "asdf")
			},
		},
		"empty version": {
			wantErr: true,
			esInfoHandler: func(w http.ResponseWriter, r *http.Request) {
				esBaseURLEndpoint(w, r, "")
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(test.esInfoHandler))
			defer ts.Close()

			client, err := NewClient(&ClientConfig{
				Username: "fizz",
				Password: "buzz",
				BaseURL:  ts.URL,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = client.setSecurityPath(ctx)
			if (err != nil) != (test.wantErr) {
				t.Fatalf("Expected error %v, got: %s", test.wantErr, err)
			}
			if client.securityPath != test.expectedPath {
				t.Fatalf("Expected security path %q, got %q", test.expectedPath, client.securityPath)
			}
		})
	}
}

func esBaseURLEndpoint(w http.ResponseWriter, r *http.Request, version string) {
	versionResponse := fmt.Sprintf(`{
		"version" : {
		  "number" : "%s"
		}
	}`, version)

	switch r.URL.Path {
	case "/":
		w.WriteHeader(200)
		w.Write([]byte(versionResponse))
		return
	default:
		w.WriteHeader(http.StatusBadRequest)
		resp := fmt.Sprintf(`{"error": "unsupported endpoint: %s"}`, r.URL.Path)
		w.Write([]byte(resp))
	}
}
