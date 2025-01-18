// sg-auth/pkg/clientlib/authlib/activation.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ActivationToken represents an activation token with its details.
type ActivationToken struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
}

// CreateActivationTokenInput represents the data required to create an activation token.
type CreateActivationTokenInput struct {
	UserID string `json:"user_id"`
}

// CreateActivationTokenOutput represents the data returned after successfully creating an activation token.
type CreateActivationTokenOutput struct {
	Token string `json:"token"`
}

// CreateActivationToken sends a request to the create activation token endpoint and returns the token on success.
func (c *Client) CreateActivationToken(ctx context.Context, input CreateActivationTokenInput) (*CreateActivationTokenOutput, error) {
	activationTokenURL := fmt.Sprintf("%s/activation-token", c.BaseURL)

	// Marshal the input into JSON.
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, activationTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to create activation token")
	}

	// Decode the response body.
	var output CreateActivationTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// ActivateUserInput represents the input for activating a user.
type ActivateUserInput struct {
	Token string `json:"token"`
}

// ActivateUser sends a request to the activate user endpoint and returns an error if any.
func (c *Client) ActivateUser(ctx context.Context, input ActivateUserInput) error {
	activateUserURL := fmt.Sprintf("%s/activate-user", c.BaseURL)

	// Marshal the input into JSON.
	reqBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, activateUserURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to activate user")
	}

	return nil
}

// GetActivationTokensByUserIDInput represents the input for getting activation tokens by user ID.
type GetActivationTokensByUserIDInput struct {
	UserID string `json:"user_id"`
}

// GetActivationTokensByUserIDOutput represents the data returned after successfully getting activation tokens by user ID.
type GetActivationTokensByUserIDOutput struct {
	Tokens []ActivationToken `json:"tokens"`
}

// GetActivationTokensByUserID sends a request to the get activation tokens by user ID endpoint and returns the tokens on success.
func (c *Client) GetActivationTokensByUserID(ctx context.Context, input GetActivationTokensByUserIDInput) (*GetActivationTokensByUserIDOutput, error) {
	getTokensURL := fmt.Sprintf("%s/activation-tokens?user_id=%s", c.BaseURL, input.UserID)

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getTokensURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get activation tokens")
	}

	// Decode the response body.
	var output GetActivationTokensByUserIDOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// GetActivationTokenByPlaintextInput represents the input for getting an activation token by plaintext.
type GetActivationTokenByPlaintextInput struct {
	Plaintext string `json:"plaintext"`
}

// GetActivationTokenByPlaintextOutput represents the data returned after successfully getting an activation token by plaintext.
type GetActivationTokenByPlaintextOutput struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
}

// GetActivationTokenByPlaintext sends a request to the get activation token by plaintext endpoint and returns the token on success.
func (c *Client) GetActivationTokenByPlaintext(ctx context.Context, input GetActivationTokenByPlaintextInput) (*GetActivationTokenByPlaintextOutput, error) {
	getTokenURL := fmt.Sprintf("%s/activation-token/%s", c.BaseURL, input.Plaintext)

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getTokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get activation token")
	}

	// Decode the response body.
	var output GetActivationTokenByPlaintextOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// DeleteActivationTokenInput represents the data required to delete an activation token.
type DeleteActivationTokenInput struct {
	TokenID string `json:"token_id"`
}

// DeleteActivationToken sends a request to the delete activation token endpoint and returns an error on failure.
func (c *Client) DeleteActivationToken(ctx context.Context, input DeleteActivationTokenInput) error {
	deleteTokenURL := fmt.Sprintf("%s/activation-token/%s", c.BaseURL, input.TokenID)

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteTokenURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to delete activation token")
	}

	return nil
}

// DeleteActivationTokenByUserIDInput represents the data required to delete activation tokens by user ID.
type DeleteActivationTokenByUserIDInput struct {
	UserID string `json:"user_id"`
}

// DeleteActivationTokenByUserID sends a request to the delete activation tokens by user ID endpoint and returns an error on failure.
func (c *Client) DeleteActivationTokenByUserID(ctx context.Context, input DeleteActivationTokenByUserIDInput) error {
	deleteTokenURL := fmt.Sprintf("%s/activation-token/user/%s", c.BaseURL, input.UserID)

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteTokenURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to delete activation tokens by user ID")
	}

	return nil
}

// DeleteExpiredActivationTokens sends a request to the delete expired activation tokens endpoint.
func (c *Client) DeleteExpiredActivationTokens(ctx context.Context) error {
	deleteExpiredTokensURL := fmt.Sprintf("%s/activation-token/expired", c.BaseURL)

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteExpiredTokensURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to delete expired activation tokens")
	}

	return nil
}

// VerifyActivationTokenInput represents the input required to verify an activation token.
type VerifyActivationTokenInput struct {
	Token string `json:"token"`
}

// VerifyActivationTokenOutput represents the output after verifying an activation token.
type VerifyActivationTokenOutput struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
	Valid     bool   `json:"valid"`
}

// VerifyActivationToken sends a request to verify the activation token and returns the token details on success.
func (c *Client) VerifyActivationToken(ctx context.Context, input VerifyActivationTokenInput) (*VerifyActivationTokenOutput, error) {
	verifyTokenURL := fmt.Sprintf("%s/activation-token/verify", c.BaseURL)

	// Marshal the input into JSON.
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request.
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error.
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to verify activation token")
	}

	// Decode the response body.
	var output VerifyActivationTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}
