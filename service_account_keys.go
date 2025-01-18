// sg-auth/pkg/clientlib/authlib/service_account_keys.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ServiceAccountKey represents the structure of a service account key
type ServiceAccountKey struct {
	ID               uuid.UUID `json:"id"`
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	PublicKey        []byte    `json:"public_key"`
	PrivateKey       []byte    `json:"private_key"`
	CreatedAt        time.Time `json:"created_at"`
}

// SaveServiceAccountKeyInput represents the required input to save a service account key
type SaveServiceAccountKeyInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
}

func (c *Client) SaveServiceAccountKey(ctx context.Context, input SaveServiceAccountKeyInput) (*ServiceAccountKey, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-account-keys", bytes.NewBuffer(requestBody))
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
	var createdServiceAccountKey ServiceAccountKey
	if err := json.NewDecoder(resp.Body).Decode(&createdServiceAccountKey); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &createdServiceAccountKey, nil
}

// SignDataInput represents the required input to sign data
type SignDataInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	Data             []byte    `json:"data"`
}

// SignDataOutput represents the response from the sign data API
type SignDataOutput struct {
	Signature []byte `json:"signature"`
}

func (c *Client) SignData(ctx context.Context, input SignDataInput) (*SignDataOutput, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/sign-data", bytes.NewBuffer(requestBody))
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
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var signDataOutput SignDataOutput
	if err := json.NewDecoder(resp.Body).Decode(&signDataOutput); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &signDataOutput, nil
}

// FetchPrivateKeyInput represents the required input to fetch a service account key
type FetchPrivateKeyInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
}

func (c *Client) FetchPrivateKey(ctx context.Context, input FetchPrivateKeyInput) ([]byte, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-account-keys/"+input.ServiceAccountID.String(), bytes.NewBuffer(requestBody))
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
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}
		return nil, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var fetchedPrivateKey []byte
	if err := json.NewDecoder(resp.Body).Decode(&fetchedPrivateKey); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return fetchedPrivateKey, nil
}
