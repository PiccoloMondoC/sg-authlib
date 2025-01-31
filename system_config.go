// sg-auth/pkg/clientlib/authlib/system_config.go
package authlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// GetConfigByKey fetches a specific system configuration value from auth-service.
func (c *Client) GetConfigByKey(ctx context.Context, key string) (string, error) {
	url := fmt.Sprintf("%s/config?key=%s", c.BaseURL, key)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch config, status: %d", resp.StatusCode)
	}

	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return response["value"], nil
}


// GetAllConfigs fetches all system configuration values from auth-service.
func (c *Client) GetAllConfigs(ctx context.Context) (map[string]string, error) {
	url := fmt.Sprintf("%s/configs", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch configs, status: %d", resp.StatusCode)
	}

	var configs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return configs, nil
}


// GetAuthServiceURL retrieves the auth_service_url from auth-service.
func (c *Client) GetAuthServiceURL(ctx context.Context) (string, error) {
	return c.GetConfigByKey(ctx, "auth_service_url")
}
