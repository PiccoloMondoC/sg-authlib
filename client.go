// sg-auth/pkg/clientlib/authlib/authclient.go
package authlib

import (
	"crypto/ed25519"
	"net/http"
	"time"
)

// Client represents an HTTP client that can be used to send requests to the authentication server.
type Client struct {
	BaseURL    string
	HttpClient *http.Client
	ApiKey     string
	PublicKey  ed25519.PublicKey
}

// ErrorResponse represents the structure of an error response
type ErrorResponse struct {
	Message string `json:"message"`
}

func NewClient(baseURL string, apiKey string, httpClient ...*http.Client) *Client {
	var client *http.Client
	if len(httpClient) > 0 {
		client = httpClient[0]
	} else {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	return &Client{
		BaseURL:    baseURL,
		HttpClient: client,
		ApiKey:     apiKey,
	}
}
