// sg-auth/pkg/clientlib/authlib/refresh_tokens.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents the structure of a refresh token
type RefreshToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash []byte    `json:"token_hash"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsRevoked bool      `json:"is_revoked"`
}

// CreateRefreshTokenInput represents the required input to create a refresh token
type CreateRefreshTokenInput struct {
	UserID    uuid.UUID `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateRefreshToken creates a new refresh token
func (c *Client) CreateRefreshToken(ctx context.Context, input CreateRefreshTokenInput) (*RefreshToken, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/refresh-tokens", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusCreated {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var createdRefreshToken RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&createdRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &createdRefreshToken, nil
}

// GetRefreshTokenInput defines the input for GetRefreshToken function.
type GetRefreshTokenInput struct {
	TokenID uuid.UUID `json:"token_id"`
}

// GetRefreshToken fetches the refresh token from the auth server.
func (c *Client) GetRefreshToken(ctx context.Context, input GetRefreshTokenInput) (*RefreshToken, error) {
	// Define the URL
	url := fmt.Sprintf("%s/refresh_token/%s", c.BaseURL, input.TokenID)

	// Define a new HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Set the required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	// Send the request via HTTP client
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the HTTP response status
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %v", err)
		}
		return nil, fmt.Errorf("received bad response from auth server: %s", errResp.Message)
	}

	// Decode the response
	var token RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token: %v", err)
	}

	return &token, nil
}

// GetRefreshTokensForUserInput represents the input parameters for the GetRefreshTokensForUser function.
type GetRefreshTokensForUserInput struct {
	UserID uuid.UUID
}

// GetRefreshTokensForUser sends a request to the authentication server to get all refresh tokens for a specific user.
func (c *Client) GetRefreshTokensForUser(ctx context.Context, input GetRefreshTokensForUserInput) ([]RefreshToken, error) {
	// Build the URL for the request
	url := fmt.Sprintf("%s/refresh_tokens/%s", c.BaseURL, input.UserID.String())

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add the API key to the request header
	req.Header.Add("X-Api-Key", c.ApiKey)

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the response body
	var tokens []RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return tokens, nil
}

type ValidateRefreshTokenInput struct {
	RefreshTokenID uuid.UUID
	UserID         uuid.UUID
}

type ValidateRefreshTokenResponse struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message,omitempty"`
}

func (c *Client) ValidateRefreshToken(ctx context.Context, input ValidateRefreshTokenInput) (bool, error) {
	url := fmt.Sprintf("%s/refresh_tokens/validate", c.BaseURL)
	body, err := json.Marshal(input)
	if err != nil {
		return false, fmt.Errorf("error marshalling input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return false, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("error reading error response body: %w", err)
		}
		errResp := ErrorResponse{}
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return false, fmt.Errorf("error unmarshalling error response body: %w", err)
		}
		return false, errors.New(errResp.Message)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %w", err)
	}

	validateResp := ValidateRefreshTokenResponse{}
	if err := json.Unmarshal(bodyBytes, &validateResp); err != nil {
		return false, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return validateResp.IsValid, nil
}

// RevokeRefreshTokenInput represents the input parameters for RevokeRefreshToken function
type RevokeRefreshTokenInput struct {
	Context        context.Context
	RefreshTokenID uuid.UUID
}

// RevokeRefreshToken revokes a refresh token by sending a POST request to the auth server.
func (c *Client) RevokeRefreshToken(input RevokeRefreshTokenInput) error {
	url := fmt.Sprintf("%s/v1/tokens/revoke", c.BaseURL)

	body, err := json.Marshal(map[string]uuid.UUID{
		"refresh_token_id": input.RefreshTokenID,
	})
	if err != nil {
		return fmt.Errorf("unable to marshal refresh_token_id: %w", err)
	}

	req, err := http.NewRequestWithContext(input.Context, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err = json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

type RevokeAllRefreshTokensInput struct {
	UserID uuid.UUID
}

func (c *Client) RevokeAllRefreshTokensForUser(ctx context.Context, input RevokeAllRefreshTokensInput) error {
	url := fmt.Sprintf("%s/revoke_refresh_tokens", c.BaseURL)

	reqBody, err := json.Marshal(input)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errorResponse)
		if err != nil {
			return err
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

// DeleteExpiredRefreshTokensInput represents the input for DeleteExpiredRefreshTokens
type DeleteExpiredRefreshTokensInput struct {
	Before time.Time `json:"before"`
}

func (c *Client) DeleteExpiredRefreshTokens(ctx context.Context, input DeleteExpiredRefreshTokensInput) error {
	// Prepare the endpoint URL
	url := fmt.Sprintf("%s/refresh-tokens", c.BaseURL)

	// Prepare the DELETE request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key to the request header
	req.Header.Add("X-API-Key", c.ApiKey)

	// Make the request using the HttpClient
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		var errorResponse ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
			return fmt.Errorf("failed to unmarshal error response: %w", err)
		}

		return errors.New(errorResponse.Message)
	}

	// If we reached here, it means the request was successful
	return nil
}

type IsRevokedResponse struct {
	IsRevoked bool `json:"is_revoked"`
}

type CheckRevokedInput struct {
	TokenID uuid.UUID
	Ctx     context.Context
}

func (c *Client) IsRefreshTokenRevoked(input CheckRevokedInput) (bool, error) {
	// Create the URL for the request
	url := fmt.Sprintf("%s/refresh-tokens/%s", c.BaseURL, input.TokenID)

	// Create a new request
	req, err := http.NewRequestWithContext(input.Ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return false, fmt.Errorf("unable to decode error response: %v", err)
		}
		return false, fmt.Errorf("server responded with error: %s", errResp.Message)
	}

	// Decode the response body
	var revokedResp IsRevokedResponse
	if err := json.NewDecoder(resp.Body).Decode(&revokedResp); err != nil {
		return false, fmt.Errorf("unable to decode response: %v", err)
	}

	// Return the IsRevoked status
	return revokedResp.IsRevoked, nil
}
