// sg-auth/pkg/clientlib/authlib/token_service.go
package authlib

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
	PrivateKey ed25519.PrivateKey
	TokenTTL   time.Duration
}

type AuthRequest struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
}

type AuthenticateServiceAccountError struct {
	BaseError  error
	StatusCode int
}

func (e *AuthenticateServiceAccountError) Error() string {
	return fmt.Sprintf("authentication failed with status code %d: %v", e.StatusCode, e.BaseError)
}

type AuthResponse struct {
	Token string `json:"token"`
}

// GenerateAccessTokenInput represents the required input to generate an access token
type GenerateAccessTokenInput struct {
	AccountID string `json:"account_id"`
	SecretKey string `json:"secret_key"`
}

// GenerateAccessToken generates and returns a new access token
func (c *Client) GenerateAccessToken(ctx context.Context, input GenerateAccessTokenInput, privateKey ed25519.PrivateKey, tokenTTL time.Duration) (string, error) {
	// Convert GenerateAccessTokenInput to AuthRequest
	authReq := AuthRequest(input)

	authReqJSON, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to encode authentication request body: %w", err)
	}

	// Construct authentication request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/authenticate", bytes.NewBuffer(authReqJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create authentication request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute authentication request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute authentication request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		var authErr AuthenticateServiceAccountError
		authErr.StatusCode = resp.StatusCode
		if err := json.NewDecoder(resp.Body).Decode(&authErr.BaseError); err != nil {
			return "", fmt.Errorf("authentication failed with status code %d: %w", authErr.StatusCode, err)
		}
		return "", &authErr
	}

	// Decode authentication response
	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode authentication response: %w", err)
	}

	// Generate JWT token with claims
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    input.AccountID,                  // Customize issuer as needed
		Subject:   authResp.Token,                  // Token as subject
		NotBefore: jwt.NewNumericDate(now),         // Use jwt.NewNumericDate for time conversion
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)), // Use the provided tokenTTL
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return signedToken, nil
}

// ValidateAccessToken validates the provided access token
func (c *Client) ValidateAccessToken(ctx context.Context, accessToken string) (*jwt.Token, error) {
	// Parse the token
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return public key for verification
		return &c.PublicKey, nil
	})

	// Check if token is valid
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("access token is not valid")
	}

	return token, nil
}

// DecodeAccessToken decodes the provided access token and returns the parsed claims
func (c *Client) DecodeAccessToken(accessToken string) (*jwt.Token, error) {
	// Parse the token
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return public key for verification
		return &c.PublicKey, nil
	})

	// Check if token is valid
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("access token is not valid")
	}

	return token, nil
}

// Account represents an entity (user or service account) that can authenticate.
type UserAccount interface {
	GetAccountID() string
	GetCredentials() string
}

// GetTokenForUser sends a request to the auth server to get a token for an account (user or service account).
func (c *Client) GetTokenForUser(ctx context.Context, account UserAccount) (string, error) {
	// Create the JSON request body
	reqBody := AuthRequest{ // This is wrongly referencing service accounts
		AccountID: account.GetAccountID(),
		SecretKey: account.GetCredentials(), // Adjusted to use GetCredentials
	}

	// Marshal the request body to JSON
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/tokens", bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create new request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.ApiKey)

	// Send the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return "", &AuthenticateServiceAccountError{ // This is wrongly referencing service accounts
			BaseError:  errors.New("failed to authenticate account"),
			StatusCode: resp.StatusCode,
		}
	}

	// Decode the response body
	var authResp AuthResponse // This may be wrongly referencing service accounts
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResp.Token, nil
}
