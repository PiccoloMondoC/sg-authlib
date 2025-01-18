// sg-auth/pkg/clientlib/authlib/service_account_tokens.go
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

// ServiceAccountToken represents the structure of a service account token
type ServiceAccountToken struct {
	ID                    uuid.UUID `json:"id"`
	ServiceAccountID      uuid.UUID `json:"service_account_id"`
	Token                 string    `json:"token"`
	RefreshToken          string    `json:"refresh_token"`
	IssuedAt              time.Time `json:"issued_at"`
	TokenExpiresAt        time.Time `json:"token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

// TokenDetails represents the structure of issued tokens and their expiry details
type TokenDetails struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AtExpires    int64  `json:"at_expires"`
	RtExpires    int64  `json:"rt_expires"`
}

// IssueServiceAccountTokenInput represents the required input to issue a service account token
type IssueServiceAccountTokenInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
}

func (c *Client) IssueServiceAccountToken(ctx context.Context, input IssueServiceAccountTokenInput) (*ServiceAccountToken, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-account-tokens", bytes.NewBuffer(requestBody))
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
	var issuedToken ServiceAccountToken
	if err := json.NewDecoder(resp.Body).Decode(&issuedToken); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &issuedToken, nil
}

// RefreshServiceAccountTokenInput represents the required input to refresh a service account token
type RefreshServiceAccountTokenInput struct {
	ServiceAccountTokenID uuid.UUID `json:"service_account_token_id"`
	RefreshToken          string    `json:"refresh_token"`
}

func (c *Client) RefreshServiceAccountToken(ctx context.Context, input RefreshServiceAccountTokenInput) (*TokenDetails, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/service-account-tokens/%s/refresh", c.BaseURL, input.ServiceAccountTokenID), bytes.NewBuffer(requestBody))
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
	var refreshedToken TokenDetails
	if err := json.NewDecoder(resp.Body).Decode(&refreshedToken); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &refreshedToken, nil
}

// InvalidateServiceAccountTokenInput represents the required input to invalidate a service account token
type InvalidateServiceAccountTokenInput struct {
	ServiceAccountTokenID uuid.UUID `json:"service_account_token_id"`
}

func (c *Client) InvalidateServiceAccountToken(ctx context.Context, input InvalidateServiceAccountTokenInput) error {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/service-account-tokens/"+input.ServiceAccountTokenID.String(), bytes.NewBuffer(requestBody))
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
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

type VerifyServiceAccountTokenInput struct {
	ServiceAccountTokenID uuid.UUID `json:"service_account_token_id"`
}

func (c *Client) VerifyServiceAccountToken(ctx context.Context, input VerifyServiceAccountTokenInput) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/service-account-tokens/%s", c.BaseURL, input.ServiceAccountTokenID), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return false, fmt.Errorf("failed to decode error response: %w", err)
		}
		return false, errors.New(errorResponse.Message)
	}

	var verificationResponse struct {
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verificationResponse); err != nil {
		return false, fmt.Errorf("failed to decode successful response: %w", err)
	}
	return verificationResponse.Verified, nil
}

// GetServiceAccountTokenMetadataInput represents the required input to get a service account token metadata
type GetServiceAccountTokenMetadataInput struct {
	ServiceAccountTokenID uuid.UUID `json:"service_account_token_id"`
}

func (c *Client) GetServiceAccountTokenMetadata(ctx context.Context, input GetServiceAccountTokenMetadataInput) (*ServiceAccountToken, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-account-tokens/"+input.ServiceAccountTokenID.String(), bytes.NewBuffer(requestBody))
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
	var tokenMetadata ServiceAccountToken
	if err := json.NewDecoder(resp.Body).Decode(&tokenMetadata); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &tokenMetadata, nil
}

// ListServiceAccountTokensInput represents the required input to list service account tokens
type ListServiceAccountTokensInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id,omitempty"` // optional
}

func (c *Client) ListServiceAccountTokens(ctx context.Context, input ListServiceAccountTokensInput) ([]ServiceAccountToken, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-account-tokens", bytes.NewBuffer(requestBody))
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
	var issuedTokens []ServiceAccountToken
	if err := json.NewDecoder(resp.Body).Decode(&issuedTokens); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return issuedTokens, nil
}

// RetrieveServiceAccountToken retrieves or refreshes a service account token
func (c *Client) RetrieveServiceAccountToken(ctx context.Context, serviceAccountID uuid.UUID) (*TokenDetails, error) {
	// Check if the token exists and is valid
	verified, err := c.VerifyServiceAccountToken(ctx, VerifyServiceAccountTokenInput{
		ServiceAccountTokenID: serviceAccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	// If the token is verified, return it
	if verified {
		refreshToken := "" // Fill in with the refresh token

		// Refresh the token
		refreshedToken, err := c.RefreshServiceAccountToken(ctx, RefreshServiceAccountTokenInput{
			ServiceAccountTokenID: serviceAccountID,
			RefreshToken:          refreshToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		return refreshedToken, nil
	}

	// Token does not exist or is invalid, issue a new token
	issuedToken, err := c.IssueServiceAccountToken(ctx, IssueServiceAccountTokenInput{
		ServiceAccountID: serviceAccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue token: %w", err)
	}

	// If token issuance is successful, return the details
	return &TokenDetails{
		AccessToken:  issuedToken.Token,
		RefreshToken: issuedToken.RefreshToken,
		AtExpires:    issuedToken.TokenExpiresAt.Unix(),
		RtExpires:    issuedToken.RefreshTokenExpiresAt.Unix(),
	}, nil
}
