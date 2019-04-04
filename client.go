package elasticsearch

/*
This lightweight client implements only the methods needed for this secrets engine.
It consumes this API:
https://www.elastic.co/guide/en/elasticsearch/reference/6.6/security-api.html
*/

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	rootcerts "github.com/hashicorp/go-rootcerts"
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

func NewClient(config *ClientConfig) (*Client, error) {
	httpClient := cleanhttp.DefaultClient()
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
		httpClient.Transport = &http.Transport{TLSClientConfig: conf}
	}
	return &Client{
		username:   config.Username,
		password:   config.Password,
		baseURL:    config.BaseURL,
		httpClient: httpClient,
	}, nil
}

type Client struct {
	username, password, baseURL string
	httpClient                  *http.Client
}

// Role management

func (c *Client) CreateRole(done <-chan struct{}, name string, role map[string]interface{}) error {
	endpoint := "/_xpack/security/role/" + name
	method := http.MethodPost

	roleBytes, err := json.Marshal(role)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(roleBytes))
	if err != nil {
		return err
	}
	return c.do(done, req, nil)
}

// GetRole returns nil, nil if role is unfound.
func (c *Client) GetRole(done <-chan struct{}, name string) (map[string]interface{}, error) {
	endpoint := "/_xpack/security/role/" + name
	method := http.MethodGet

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	var roles map[string]map[string]interface{}
	if err := c.do(done, req, &roles); err != nil {
		return nil, err
	}
	return roles[name], nil
}

func (c *Client) DeleteRole(done <-chan struct{}, name string) error {
	endpoint := "/_xpack/security/role/" + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(done, req, nil)
}

// User management

type User struct {
	Password string   `json:"password"` // Passwords must be at least 6 characters long.
	Roles    []string `json:"roles"`
}

func (c *Client) CreateUser(done <-chan struct{}, name string, user *User) error {
	endpoint := "/_xpack/security/user/" + name
	method := http.MethodPost

	userJson, err := json.Marshal(user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(userJson))
	if err != nil {
		return err
	}
	return c.do(done, req, nil)
}

func (c *Client) ChangePassword(done <-chan struct{}, name, newPassword string) error {
	endpoint := "/_xpack/security/user/" + name + "/_password"
	method := http.MethodPost

	pwdChangeBodyJson, err := json.Marshal(map[string]string{"password": newPassword})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(pwdChangeBodyJson))
	if err != nil {
		return err
	}
	return c.do(done, req, nil)
}

func (c *Client) DeleteUser(done <-chan struct{}, name string) error {
	endpoint := "/_xpack/security/user/" + name
	method := http.MethodDelete

	req, err := http.NewRequest(method, c.baseURL+endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(done, req, nil)
}

// Low-level request handling

func (c *Client) do(done <-chan struct{}, req *http.Request, ret interface{}) error {

	req.SetBasicAuth(c.username, c.password)
	req.Header.Add("Content-Type", "application/json")

	expBackoff := backoff.NewExponentialBackOff()
	backoffTimer := time.NewTimer(0)
	var lastErr error
	for tries := 0; tries < 10; tries++ {

		if tries != 0 {
			backoffTimer.Reset(expBackoff.NextBackOff())
			select {
			case <-done:
				return nil
			case <-backoffTimer.C:
			}
		}

		retryable, err := c.doRequest(req, ret)
		if err == nil {
			return nil
		}
		if !retryable {
			return err
		}
		lastErr = err
	}
	return lastErr
}

// doRequest attemtps to execute a request once.
// If the err is nil, the request was successful. ret may or may not be nil.
// If the err is populated, retryable may be checked to determine whether to try again.
func (c *Client) doRequest(req *http.Request, ret interface{}) (retryable bool, err error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
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
			return false, nil
		}
		if err := json.Unmarshal(body, ret); err != nil {
			// We received a success response from the ES API but the body was in an unexpected format.
			return false, fmt.Errorf("%s; %d: %s", err, resp.StatusCode, body)
		}
		// Body has been successfully read out.
		return false, nil
	}

	// 404 is actually another form of success in the ES API. It just means that an object we were searching
	// for wasn't found.
	if resp.StatusCode == 404 {
		return false, nil
	}

	// We received some sort of API error. Let's read what we got into a returnable error.
	respErr := fmt.Errorf("%d: %s", resp.StatusCode, body)

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// There's something permanently wrong with the request we're sending.
		return false, respErr
	}
	// Let's retry on everything else - 5XX's and other things.
	return true, respErr
}
