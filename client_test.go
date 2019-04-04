package elasticsearch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/vault-plugin-database-elasticsearch/test-fixtures"
)

const (
	esHome     = "/home/somewhere/Applications/elasticsearch-6.6.1"
	esUsername = "fizz"
	esPassword = "buzz"
)

var testDoneChan = context.Background().Done()

func TestClient_CreateListGetDeleteRole(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(handleRequests))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: esUsername,
		Password: esPassword,
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRole(testDoneChan, "role-name", map[string]interface{}{
		"cluster": []string{"manage_security"},
	}); err != nil {
		t.Fatal(err)
	}
	role, err := client.GetRole(testDoneChan, "role-name")
	if err != nil {
		t.Fatal(err)
	}
	clusterValue := fmt.Sprintf("%s", role["cluster"])
	if clusterValue != "[all]" {
		t.Fatalf("expected manage_security but received %s", clusterValue)
	}
	if err := client.DeleteRole(testDoneChan, "role-name"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CreateGetDeleteUser(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(handleRequests))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: esUsername,
		Password: esPassword,
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateUser(testDoneChan, "user-name", &User{
		Password: "pa55w0rd",
		Roles:    []string{"vault"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.ChangePassword(testDoneChan, "user-name", "newPa55w0rd"); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteUser(testDoneChan, "user-name"); err != nil {
		t.Fatal(err)
	}
}

func TestTLSClient(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("VAULT_ACC != 1")
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(handleRequests))
	defer ts.Close()

	tlsConfig := &TLSConfig{
		CACert:     "/usr/local/share/ca-certificates/elastic-stack-ca.crt.pem",
		ClientCert: esHome + "/config/certs/elastic-certificates.crt.pem",
		ClientKey:  esHome + "/config/certs/elastic-certificates.key.pem",
	}
	client, err := NewClient(&ClientConfig{
		Username:  esUsername,
		Password:  esPassword,
		BaseURL:   ts.URL,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient = ts.Client()

	if err := client.CreateRole(testDoneChan, "role-name", map[string]interface{}{
		"cluster": []string{"manage_security"},
	}); err != nil {
		t.Fatal(err)
	}
	role, err := client.GetRole(testDoneChan, "role-name")
	if err != nil {
		t.Fatal(err)
	}
	clusterValue := fmt.Sprintf("%s", role["cluster"])
	if clusterValue != "[all]" {
		t.Fatalf("expected manage_security but received %s", clusterValue)
	}
	if err := client.DeleteRole(testDoneChan, "role-name"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_BadResponses(t *testing.T) {
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("VAULT_ACC != 1")
	}
	ts := httptest.NewServer(http.HandlerFunc(giveBadResponses))
	defer ts.Close()

	client, err := NewClient(&ClientConfig{
		Username: esUsername,
		Password: esPassword,
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRole(testDoneChan, "200-but-body-changed"); err.Error() != "invalid character '<' looking for beginning of value; 200: <html>I switched to html!</html>" {
		t.Fatal(`expected "invalid character '<' looking for beginning of value; 200: <html>I switched to html!</html>"`)
	}
	if role, err := client.GetRole(testDoneChan, "404-not-found"); err != nil || role != nil {
		// We shouldn't error on 404s because they are a success case.
		t.Fatal(err)
	}
	if _, err := client.GetRole(testDoneChan, "500-mysterious-internal-server-error"); err.Error() != "500: <html>Internal Server Error</html>" {
		t.Fatal(`expected "500: <html>Internal Server Error</html>"`)
	}
	if _, err := client.GetRole(testDoneChan, "503-unavailable"); err.Error() != "503: <html>Service Unavailable</html>" {
		t.Fatal(`expected "503: <html>Service Unavailable</html>"`)
	}
}

func handleRequests(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_xpack/security/role/role-name":
		switch r.Method {
		case http.MethodPost:
			w.Write([]byte(fixtures.CreateRoleResponse))
			return
		case http.MethodGet:
			w.Write([]byte(fixtures.GetRoleResponse))
			return
		case http.MethodDelete:
			w.Write([]byte(fixtures.DeleteRoleResponse))
			return
		}
	case "/_xpack/security/user/user-name":
		switch r.Method {
		case http.MethodPost:
			w.Write([]byte(fixtures.CreateUserResponse))
			return
		case http.MethodDelete:
			w.Write([]byte(fixtures.DeleteUserResponse))
			return
		}
	case "/_xpack/security/user/user-name/_password":
		switch r.Method {
		case http.MethodPost:
			w.Write([]byte(fixtures.ChangePasswordResponse))
			return
		}
	}
	// We received an unexpected request.
	w.WriteHeader(404)
	w.Write([]byte(fmt.Sprintf("%s to %s is unsupported", r.Method, r.URL.Path)))
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
