// sg-auth/pkg/clientlib/authlib/password-reset.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// PasswordResetToken represents a password reset token with its details
type PasswordResetToken struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
}

// PasswordResetTokenInput represents the data required to create a password reset token
type PasswordResetTokenInput struct {
	Email string `json:"email"`
}

// CreatePasswordResetTokenOutput represents the data returned after successfully creating a password reset token
type CreatePasswordResetTokenOutput struct {
	Token string `json:"token"`
}
 
// CreatePasswordResetToken sends a request to the create password reset token endpoint and returns the token on success
func (c *Client) CreatePasswordResetToken(ctx context.Context, input PasswordResetTokenInput) (*CreatePasswordResetTokenOutput, error) {
	resetTokenURL := fmt.Sprintf("%s/password-reset", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to create password reset token")
	}

	// Decode the response body
	var output CreatePasswordResetTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// ProcessPasswordResetInput represents the data required to process a password reset
type ProcessPasswordResetInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ProcessPasswordResetOutput represents the data returned after successfully processing a password reset
type ProcessPasswordResetOutput struct {
	UserID string `json:"user_id"`
}

// ProcessPasswordReset sends a request to the process password reset endpoint and returns the response on success
func (c *Client) ProcessPasswordReset(ctx context.Context, input ProcessPasswordResetInput) (*ProcessPasswordResetOutput, error) {
	resetPasswordURL := fmt.Sprintf("%s/password-reset/confirm", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetPasswordURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to process password reset")
	}

	// Decode the response body
	var output ProcessPasswordResetOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// CreateAndProcessPasswordResetInput represents the combined input for creating and processing a password reset
type CreateAndProcessPasswordResetInput struct {
	Email       string `json:"email"`
	NewPassword string `json:"new_password"`
}

// CreateAndProcessPasswordResetOutput represents the combined output for creating and processing a password reset
type CreateAndProcessPasswordResetOutput struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
}

// CreateAndProcessPasswordReset handles both the creation of the reset token and the password reset process
func (c *Client) CreateAndProcessPasswordReset(ctx context.Context, input CreateAndProcessPasswordResetInput) (*CreateAndProcessPasswordResetOutput, error) {
	// Create the password reset token
	createTokenOutput, err := c.CreatePasswordResetToken(ctx, PasswordResetTokenInput{Email: input.Email})
	if err != nil {
		return nil, fmt.Errorf("failed to create password reset token: %w", err)
	}

	// Process the password reset using the created token
	processResetOutput, err := c.ProcessPasswordReset(ctx, ProcessPasswordResetInput{
		Token:       createTokenOutput.Token,
		NewPassword: input.NewPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to process password reset: %w", err)
	}

	return &CreateAndProcessPasswordResetOutput{
		Token:  createTokenOutput.Token,
		UserID: processResetOutput.UserID,
	}, nil
}

// GetPasswordResetTokensByUserIDInput represents the data required to get password reset tokens by user ID
type GetPasswordResetTokensByUserIDInput struct {
	UserID string `json:"user_id"`
}

// GetPasswordResetTokensByUserIDOutput represents the data returned after successfully retrieving password reset tokens
type GetPasswordResetTokensByUserIDOutput struct {
	Tokens []PasswordResetToken `json:"tokens"`
}

// GetPasswordResetTokensByUserID sends a request to the get password reset tokens endpoint and returns the tokens on success
func (c *Client) GetPasswordResetTokensByUserID(ctx context.Context, input GetPasswordResetTokensByUserIDInput) (*GetPasswordResetTokensByUserIDOutput, error) {
	resetTokensURL := fmt.Sprintf("%s/password-reset-tokens", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetTokensURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve password reset tokens")
	}

	// Decode the response body
	var output GetPasswordResetTokensByUserIDOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// GetPasswordResetTokenByPlaintextInput represents the data required to get a password reset token by plaintext
type GetPasswordResetTokenByPlaintextInput struct {
	Plaintext string `json:"plaintext"`
}

// GetPasswordResetTokenByPlaintextOutput represents the data returned after successfully retrieving a password reset token
type GetPasswordResetTokenByPlaintextOutput struct {
	Token PasswordResetToken `json:"token"`
}

// GetPasswordResetTokenByPlaintext sends a request to the get password reset token by plaintext endpoint and returns the token on success
func (c *Client) GetPasswordResetTokenByPlaintext(ctx context.Context, input GetPasswordResetTokenByPlaintextInput) (*GetPasswordResetTokenByPlaintextOutput, error) {
	resetTokenURL := fmt.Sprintf("%s/password-reset-token", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve password reset token")
	}

	// Decode the response body
	var output GetPasswordResetTokenByPlaintextOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// DeletePasswordResetTokenInput represents the data required to delete a password reset token
type DeletePasswordResetTokenInput struct {
	TokenID string `json:"token_id"`
}

// DeletePasswordResetTokenOutput represents the data returned after successfully deleting a password reset token
type DeletePasswordResetTokenOutput struct {
	Message string `json:"message"`
}

// DeletePasswordResetToken sends a request to delete a password reset token by its ID
func (c *Client) DeletePasswordResetToken(ctx context.Context, input DeletePasswordResetTokenInput) (*DeletePasswordResetTokenOutput, error) {
	deleteTokenURL := fmt.Sprintf("%s/password-reset/%s", c.BaseURL, input.TokenID)

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteTokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to delete password reset token")
	}

	// Decode the response body
	var output DeletePasswordResetTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// DeletePasswordResetTokenByUserIDInput represents the data required to delete password reset tokens by user ID
type DeletePasswordResetTokenByUserIDInput struct {
	UserID string `json:"user_id"`
}

// DeletePasswordResetTokenByUserIDOutput represents the data returned after successfully deleting password reset tokens by user ID
type DeletePasswordResetTokenByUserIDOutput struct {
	Message string `json:"message"`
}

// DeletePasswordResetTokenByUserID sends a request to delete password reset tokens for a specific user ID
func (c *Client) DeletePasswordResetTokenByUserID(ctx context.Context, input DeletePasswordResetTokenByUserIDInput) (*DeletePasswordResetTokenByUserIDOutput, error) {
	deleteTokenURL := fmt.Sprintf("%s/password-reset/user/%s", c.BaseURL, input.UserID)

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteTokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to delete password reset tokens by user ID")
	}

	// Decode the response body
	var output DeletePasswordResetTokenByUserIDOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// DeleteExpiredPasswordResetTokensInput represents the data required to delete expired password reset tokens
type DeleteExpiredPasswordResetTokensInput struct{}

// DeleteExpiredPasswordResetTokensOutput represents the data returned after successfully deleting expired password reset tokens
type DeleteExpiredPasswordResetTokensOutput struct {
	Message string `json:"message"`
}

// DeleteExpiredPasswordResetTokens sends a request to delete expired password reset tokens
func (c *Client) DeleteExpiredPasswordResetTokens(ctx context.Context, input DeleteExpiredPasswordResetTokensInput) (*DeleteExpiredPasswordResetTokensOutput, error) {
	deleteTokensURL := fmt.Sprintf("%s/password-reset/expired", c.BaseURL)

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteTokensURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to delete expired password reset tokens")
	}

	// Decode the response body
	var output DeleteExpiredPasswordResetTokensOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// VerifyPasswordResetTokenInput represents the input required to verify a password reset token
type VerifyPasswordResetTokenInput struct {
	Token string `json:"token"`
}

// VerifyPasswordResetTokenOutput represents the data returned after successfully verifying a password reset token
type VerifyPasswordResetTokenOutput struct {
	Valid bool `json:"valid"`
}

// VerifyPasswordResetToken sends a request to verify a password reset token
func (c *Client) VerifyPasswordResetToken(ctx context.Context, input VerifyPasswordResetTokenInput) (*VerifyPasswordResetTokenOutput, error) {
	verifyTokenURL := fmt.Sprintf("%s/password-reset/verify", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to verify password reset token")
	}

	// Decode the response body
	var output VerifyPasswordResetTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// ValidatePasswordResetTokenInput represents the input required to validate a password reset token
type ValidatePasswordResetTokenInput struct {
	Token string `json:"token"`
}

// ValidatePasswordResetTokenOutput represents the data returned after successfully validating a password reset token
type ValidatePasswordResetTokenOutput struct {
	Valid     bool   `json:"valid"`
	CreatedAt string `json:"createdAt"`
	Expiry    string `json:"expiry"`
}

// ValidatePasswordResetToken sends a request to validate a password reset token
func (c *Client) ValidatePasswordResetToken(ctx context.Context, input ValidatePasswordResetTokenInput) (*ValidatePasswordResetTokenOutput, error) {
	validateTokenURL := fmt.Sprintf("%s/password-reset/validate", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, validateTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to validate password reset token")
	}

	// Decode the response body
	var output ValidatePasswordResetTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}
