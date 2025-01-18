// sg-auth/pkg/clientlib/authlib/token_blacklist.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// TokenBlacklist represents the structure of a blacklisted token
type TokenBlacklist struct {
	Token     []byte    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

// BlacklistToken blacklists the given token
func (c *Client) BlacklistToken(ctx context.Context, token []byte) error {
	// Prepare the request body
	input := TokenBlacklist{
		Token:     token,
		CreatedAt: time.Now(),
	}
	requestBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/token-blacklist", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusCreated {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

// IsTokenBlacklisted checks if the given token is blacklisted
func (c *Client) IsTokenBlacklisted(ctx context.Context, token []byte) (bool, error) {
	// Construct the URL with the token
	url := fmt.Sprintf("%s/token-blacklist/%s", c.BaseURL, string(token))

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// Token not found in blacklist
			return false, nil
		}
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return false, fmt.Errorf("failed to decode error response: %w", err)
		}
		return false, errors.New(errorResponse.Message)
	}

	// Token found in blacklist
	return true, nil
}

// RemoveTokenFromBlacklist removes the given token from the blacklist
func (c *Client) RemoveTokenFromBlacklist(ctx context.Context, token []byte) error {
	// Construct the URL with the token
	url := fmt.Sprintf("%s/token-blacklist/%s", c.BaseURL, string(token))

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

// ListBlacklistedTokens retrieves the list of blacklisted tokens
func (c *Client) ListBlacklistedTokens(ctx context.Context) ([]TokenBlacklist, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/token-blacklist", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var blacklistedTokens []TokenBlacklist
	if err := json.NewDecoder(resp.Body).Decode(&blacklistedTokens); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return blacklistedTokens, nil
}

// ClearBlacklist clears the blacklist of tokens
func (c *Client) ClearBlacklist(ctx context.Context) error {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/token-blacklist", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

// CountBlacklistedTokens gets the count of blacklisted tokens
func (c *Client) CountBlacklistedTokens(ctx context.Context) (int, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/token-blacklist/count", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return 0, fmt.Errorf("failed to decode error response: %w", err)
		}
		return 0, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var count int
	if err := json.NewDecoder(resp.Body).Decode(&count); err != nil {
		return 0, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return count, nil
}

// GetBlacklistedTokenDetails retrieves details of a blacklisted token
func (c *Client) GetBlacklistedTokenDetails(ctx context.Context, token []byte) (*TokenBlacklist, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/token-blacklist/%s", c.BaseURL, token), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var tokenDetails TokenBlacklist
	if err := json.NewDecoder(resp.Body).Decode(&tokenDetails); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &tokenDetails, nil
}
