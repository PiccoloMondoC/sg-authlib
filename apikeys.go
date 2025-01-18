// sg-auth/pkg/clientlib/authlib/apikeys.go
package authlib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type APIKey struct {
	ID               uuid.UUID `json:"id"`
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	APIKey           string    `json:"api_key"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Valid            bool      `json:"valid"`
	IsActive         bool      `json:"is_active"`
	ServiceName      string    `json:"service_name"`
}

type ValidateResponse struct {
	IsValid bool `json:"is_valid"`
}

func (c *Client) CreateAPIKey(apiKey APIKey) (APIKey, error) {
	apiKeyJSON, err := json.Marshal(apiKey)
	if err != nil {
		return APIKey{}, err
	}

	url := fmt.Sprintf("%s/apikeys", c.BaseURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(apiKeyJSON))
	if err != nil {
		return APIKey{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return APIKey{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return APIKey{}, fmt.Errorf("create API key failed: %s", resp.Status)
	}

	var createdKey APIKey
	err = json.NewDecoder(resp.Body).Decode(&createdKey)
	if err != nil {
		return APIKey{}, err
	}

	return createdKey, nil
}

func (c *Client) GetAPIKeyByID(id uuid.UUID) (*APIKey, error) {
	// Create the URL for the request
	endpoint := fmt.Sprintf("%s/apikeys/%s", c.BaseURL, url.PathEscape(id.String()))

	// Create the GET request
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// Send the request
	res, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Check for a successful status code
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: received status code %d", res.StatusCode)
	}

	// Decode the response body into an APIKey struct
	var key APIKey
	err = json.NewDecoder(res.Body).Decode(&key)
	if err != nil {
		return nil, err
	}

	// Return the APIKey
	return &key, nil
}

func (c *Client) GetAPIKeyByAPIKey(apiKey string) (*APIKey, error) {
	url := fmt.Sprintf("%s/apikeys/key/%s", c.BaseURL, apiKey)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status code %d", resp.StatusCode)
	}

	var key APIKey
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return nil, err
	}

	return &key, nil
}

func (c *Client) UpdateAPIKey(key *APIKey) (*APIKey, error) {
	// 1. Serialize the updated APIKey into JSON
	body, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	// 2. Construct the URL for the request
	url := fmt.Sprintf("%s/apikeys/%s", c.BaseURL, key.ID)

	// 3. Create a new HTTP PUT request
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// 4. Send the request using the HTTP client
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 5. Read the response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status code %d", resp.StatusCode)
	}

	var updatedKey APIKey
	if err := json.NewDecoder(resp.Body).Decode(&updatedKey); err != nil {
		return nil, err
	}

	return &updatedKey, nil
}

// DeleteAPIKey deletes the APIKey with the given id.
func (c *Client) DeleteAPIKey(id uuid.UUID) error {
	// Create the URL for the DELETE request
	url := fmt.Sprintf("%s/apikeys/%s", c.BaseURL, id)

	// Create the DELETE request
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("create DELETE request: %w", err)
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send DELETE request: %w", err)
	}
	defer resp.Body.Close()

	// Check the status code of the response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return nil
}

// ListAPIKeys retrieves all API keys.
func (c *Client) ListAPIKeys() ([]APIKey, error) {
	// Create the URL for the GET request
	url := fmt.Sprintf("%s/apikeys", c.BaseURL)

	// Create the GET request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send GET request: %w", err)
	}
	defer resp.Body.Close()

	// Check the status code of the response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// Decode the response body into a slice of APIKey
	var apiKeys []APIKey
	err = json.NewDecoder(resp.Body).Decode(&apiKeys)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return apiKeys, nil
}

// ValidateAPIKey validates an API key.
func (c *Client) ValidateAPIKey(apikey string) (bool, error) {
	// Create the URL for the GET request
	url := fmt.Sprintf("%s/apikeys/key/%s/validate", c.BaseURL, apikey)

	// Create the GET request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("create GET request: %w", err)
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("send GET request: %w", err)
	}
	defer resp.Body.Close()

	// Check the status code of the response
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// Decode the response body into a ValidateResponse
	var validation ValidateResponse
	err = json.NewDecoder(resp.Body).Decode(&validation)
	if err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}

	return validation.IsValid, nil
}
