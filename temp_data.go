// sg-auth/pkg/clientlib/authlib/temp_data.go
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

// TemporaryData represents the structure of a temporary data entry
type TemporaryData struct {
	ID        uuid.UUID `json:"id"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) CreateTemporaryData(ctx context.Context, data []byte, ttl time.Duration) (*TemporaryData, error) {
	// Generate a new UUID for the temporary data
	id := uuid.New()

	// Set the created and expiry times
	createdAt := time.Now()
	expiresAt := createdAt.Add(ttl)

	// Create the temporary data entry
	tempData := TemporaryData{
		ID:        id,
		Data:      data,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	// JSON encode the temporary data entry
	requestBody, err := json.Marshal(tempData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/temporary-data", bytes.NewBuffer(requestBody))
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
	var newTempData TemporaryData
	if err := json.NewDecoder(resp.Body).Decode(&newTempData); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &newTempData, nil
}

func (c *Client) GetTemporaryData(ctx context.Context, id uuid.UUID) (*TemporaryData, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/temporary-data/%s", c.BaseURL, id.String())

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
	var tempData TemporaryData
	if err := json.NewDecoder(resp.Body).Decode(&tempData); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &tempData, nil
}

func (c *Client) UpdateTemporaryData(ctx context.Context, id uuid.UUID, data []byte, ttl time.Duration) (*TemporaryData, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/temporary-data/%s", c.BaseURL, id.String())

	// Set the updated expiry time
	expiresAt := time.Now().Add(ttl)

	// Create the updated temporary data entry
	updatedTempData := TemporaryData{
		ID:        id,
		Data:      data,
		ExpiresAt: expiresAt,
	}

	// JSON encode the updated temporary data entry
	requestBody, err := json.Marshal(updatedTempData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(requestBody))
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
	var updatedTempDataResp TemporaryData
	if err := json.NewDecoder(resp.Body).Decode(&updatedTempDataResp); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedTempDataResp, nil
}

func (c *Client) DeleteTemporaryData(ctx context.Context, id uuid.UUID) error {
	// Construct the URL
	url := fmt.Sprintf("%s/temporary-data/%s", c.BaseURL, id.String())

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

func (c *Client) ListTemporaryData(ctx context.Context) ([]TemporaryData, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/temporary-data", nil)
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
	var tempDataList []TemporaryData
	if err := json.NewDecoder(resp.Body).Decode(&tempDataList); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return tempDataList, nil
}

func (c *Client) DeleteExpiredTemporaryData(ctx context.Context) error {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/temporary-data/expired", nil)
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
