package elasticsearch

/*
This lightweight client implements only the methods needed for this secrets engine.
It consumes this API:
https://www.elastic.co/guide/en/elasticsearch/reference/6.6/security-api.html
*/

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-rootcerts"
	version "github.com/hashicorp/go-version"
)

type ClientConfig struct {
	Username, Password, BaseURL string

	// Leave this nil to flag that TLS is not desired
	TLSConfig *TLSConfig
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Elasticsearch.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify theHTTPClient
	// Elasticsearch server SSL certificate.
	CACert string

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Elasticsearch server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Elasticsearch communication
	ClientCert string

	// ClientKey is the path to the private key for Elasticsearch communication
	ClientKey string

	// TLSServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	TLSServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

// NewClient constructs a Client from the given config. ctx is used to set the
// x-pack security API path (which depends on the version of Elasticsearch) if
// verifyConnection is true.
func NewClient(ctx context.Context, config *ClientConfig, verifyConnection bool) (*Client, error) {
	client := retryablehttp.NewClient()
	if config.TLSConfig != nil {
		conf := &tls.Config{
			ServerName:         config.TLSConfig.TLSServerName,
			InsecureSkipVerify: config.TLSConfig.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
		if config.TLSConfig.ClientCert != "" && config.TLSConfig.ClientKey != "" {
			clientCertificate, err := tls.LoadX509KeyPair(config.TLSConfig.ClientCert, config.TLSConfig.ClientKey)
			if err != nil {
				return nil, err
			}
			conf.Certificates = append(conf.Certificates, clientCertificate)
		}
		if config.TLSConfig.CACert != "" || config.TLSConfig.CAPath != "" {
			rootConfig := &rootcerts.Config{
				CAFile: config.TLSConfig.CACert,
				CAPath: config.TLSConfig.CAPath,
			}
			if err := rootcerts.ConfigureTLS(conf, rootConfig); err != nil {
				return nil, err
			}
		}

		client.HTTPClient.Transport = &http.Transport{TLSClientConfig: conf}
	}
	c := &Client{
		username: config.Username,
		password: config.Password,
		baseURL:  config.BaseURL,
		client:   client,
	}
	if verifyConnection {
		return c, c.setSecurityPath(ctx)
	}
	return c, nil
}

type Client struct {
	username, password, baseURL string
	client                      *retryablehttp.Client
	securityPath                string
}

// Role management

func (c *Client) CreateRole(ctx context.Context, name string, role map[string]interface{}) error {
	endpoint := path.Join(c.securityPath, "/role/", name)
	method := http.MethodPost

	roleBytes, err := json.Marshal(role)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(roleBytes))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

// GetRole returns nil, nil if role is unfound.
func (c *Client) GetRole(ctx context.Context, name string) (map[string]interface{}, error) {
	endpoint := path.Join(c.securityPath, "/role/", name)
	method := http.MethodGet

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	var roles map[string]map[string]interface{}
	if err := c.do(ctx, req, &roles); err != nil {
		return nil, err
	}
	return roles[name], nil
}

func (c *Client) DeleteRole(ctx context.Context, name string) error {
	endpoint := c.securityPath + "/role/" + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

// User management

type User struct {
	Password string   `json:"password"` // Passwords must be at least 6 characters long.
	Roles    []string `json:"roles"`
}

func (c *Client) CreateUser(ctx context.Context, name string, user *User) error {
	endpoint := c.securityPath + "/user/" + name
	method := http.MethodPost

	userJson, err := json.Marshal(user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(userJson))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) ChangePassword(ctx context.Context, name, newPassword string) error {
	endpoint := path.Join(c.securityPath, "/user/", name, "/_password")
	method := http.MethodPost

	pwdChangeBodyJson, err := json.Marshal(map[string]string{"password": newPassword})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(pwdChangeBodyJson))
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *Client) DeleteUser(ctx context.Context, name string) error {
	endpoint := path.Join(c.securityPath, "/user/", name)
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

// esInfo is used to pick the elasticsearch version out of the baseURL response, example:
//
// GET /
// Response:
// {
// 	"name" : "es01",
// 	"cluster_name" : "es-cluster",
// 	"cluster_uuid" : "N1ECkSz9Qy6KY_noyom9yg",
// 	"version" : {
// 	  "number" : "6.8.13",
// ...
type esInfo struct {
	Version struct {
		Number string `json:"number"`
	} `json:"version"`
}

func (c *Client) setSecurityPath(ctx context.Context) error {
	info, err := c.getInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to getInfo: %w", err)
	}
	securityPath, err := getXPackStr(info.Version.Number)
	if err != nil {
		return err
	}
	c.securityPath = securityPath
	return nil
}

func (c *Client) getInfo(ctx context.Context) (*esInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, err
	}
	ret := &esInfo{}
	if err = c.do(ctx, req, ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func getXPackStr(versionIn string) (string, error) {
	v, err := version.NewVersion(versionIn)
	if err != nil {
		return "", fmt.Errorf("failed to parse version: %w", err)
	}
	if v.Segments()[0] < 7 {
		return "/_xpack/security", nil
	} else {
		return "/_security", nil
	}
}

// Low-level request handling

func (c *Client) do(ctx context.Context, req *http.Request, ret interface{}) error {
	// Prepare the request.
	retryableReq, err := retryablehttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return err
	}
	retryableReq.SetBasicAuth(c.username, c.password)
	retryableReq.Header.Add("Content-Type", "application/json")

	// Execute the request.
	resp, err := c.client.Do(retryableReq.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read the body once so it can be retained for error output if needed.
	// Since no responses are list responses, response bodies should have a small footprint
	// and are very useful for debugging.
	body, _ := ioutil.ReadAll(resp.Body)

	// If we were successful, try to unmarshal the body if the caller wants it.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if ret == nil {
			// No body to read out.
			return nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			// We received a success response from the ES API but the body was in an unexpected format.
			return fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		// Body has been successfully read out.
		return nil
	}

	// 404 is actually another form of success in the ES API. It just means that an object we were searching
	// for wasn't found.
	if resp.StatusCode == 404 {
		return nil
	}

	// We received some sort of API error. Let's return it.
	return fmt.Errorf("%d: %s", resp.StatusCode, body)
}
