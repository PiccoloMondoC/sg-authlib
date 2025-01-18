// sg-auth/pkg/clientlib/authlib/service_accounts.go
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

type ServiceAccount struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	Secret       string     `db:"secret" json:"-"`
	HashedSecret string     `json:"hashed_secret"`
	ServiceName  string     `db:"service_name" json:"service_name"`
	ServiceRoles []string   `json:"service_roles"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	ExpiresAt    *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	IsActive     bool       `json:"is_active"`
	APIKey       string     `json:"-"` // Omit API Key in JSON responses by default.
	AccessToken  string     `json:"-"` // Omit AccessToken in JSON responses by default.
	RefreshToken string     `json:"-"` // Omit RefreshToken in JSON responses by default.
}

type RequestServiceAccountRegistrationInput struct {
	ServiceName    string   `json:"service_name"`
	ApiKey         string   `json:"api_key,omitempty"`         // Optional, if you want to include an ApiKey
	BootstrapToken string   `json:"bootstrap_token,omitempty"` // Optional, if you want to include a BootstrapToken
	Roles          []string `json:"roles"`
}

func (c *Client) RequestServiceAccountRegistration(ctx context.Context, input RequestServiceAccountRegistrationInput) (*ServiceAccount, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-account-registration", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input.ApiKey != "" {
		req.Header.Set("X-Api-Key", input.ApiKey)
	}
	if input.BootstrapToken != "" {
		req.Header.Set("X-Bootstrap-Token", input.BootstrapToken)
	}

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
	var newServiceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&newServiceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &newServiceAccount, nil
}

type RegisterServiceAccountInput struct {
	ServiceName    string   `json:"service_name"`
	ApiKey         string   `json:"api_key,omitempty"`
	BootstrapToken string   `json:"bootstrap_token,omitempty"`
	Roles          []string `json:"roles"`
}

func (c *Client) RegisterServiceAccount(ctx context.Context, input RegisterServiceAccountInput) (*ServiceAccount, error) {
	// Convert RegisterServiceAccountInput to RequestServiceAccountRegistrationInput
	requestInput := RequestServiceAccountRegistrationInput(input)

	// Call RequestServiceAccountRegistration
	serviceAccount, err := c.RequestServiceAccountRegistration(ctx, requestInput)
	if err != nil {
		return nil, fmt.Errorf("failed to register service account: %w", err)
	}

	return serviceAccount, nil
}

func (c *Client) AuthenticateServiceAccount(ctx context.Context, serviceAccountID uuid.UUID, token string) (bool, error) {
	// Construct the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"id":    serviceAccountID,
		"token": token,
	})
	if err != nil {
		return false, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authenticate-service-account", bytes.NewBuffer(requestBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("failed to authenticate service account")
	}

	// Decode the response body
	var authResponse struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return false, fmt.Errorf("failed to decode response body: %w", err)
	}

	return authResponse.Authenticated, nil
}

func (c *Client) GetServiceAccountByID(ctx context.Context, serviceAccountID uuid.UUID) (*ServiceAccount, error) {
	// Construct the URL with the service account ID
	url := fmt.Sprintf("%s/service-accounts/%s", c.BaseURL, serviceAccountID.String())

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Optionally, you can add headers if required for authorization, etc.
	// e.g., req.Header.Set("Authorization", "Bearer "+token)

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

	// Decode the successful response into the ServiceAccount struct
	var serviceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&serviceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceAccount, nil
}

func (c *Client) GetServiceAccountByAPIKey(ctx context.Context, apiKey string) (*ServiceAccount, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/get-service-account-by-api-key", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

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
	var serviceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&serviceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceAccount, nil
}

func (c *Client) GetServiceAccountByName(ctx context.Context, serviceName string, apiKey string) (*ServiceAccount, error) {
	// Construct the URL with the service name query parameter
	url := c.BaseURL + "/service-account?service_name=" + serviceName

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
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
	var serviceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&serviceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceAccount, nil
}

type UpdateServiceAccountInput struct {
	ServiceAccount *ServiceAccount `json:"service_account"`
	ApiKey         string          `json:"api_key,omitempty"` // Optional, if you want to include an ApiKey
}

func (c *Client) UpdateServiceAccount(ctx context.Context, input UpdateServiceAccountInput) (*ServiceAccount, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "PUT", c.BaseURL+"/service-account-update", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input.ApiKey != "" {
		req.Header.Set("X-Api-Key", input.ApiKey)
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
	var updatedServiceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&updatedServiceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedServiceAccount, nil
}

func (c *Client) DeleteServiceAccount(ctx context.Context, serviceAccountID uuid.UUID, apiKey string) error {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/service-accounts/"+serviceAccountID.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusNoContent { // assuming that no content is returned on successful deletion
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

func (c *Client) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-accounts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Optional: Include any required headers, similar to how you added ApiKey and BootstrapToken
	// in the RequestServiceAccountRegistration function, if necessary

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
	var serviceAccounts []ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&serviceAccounts); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return serviceAccounts, nil
}

type AssignServiceRoleToServiceAccountInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	ServiceRoleID    uuid.UUID `json:"service_role_id"`
	ApiKey           string    `json:"api_key,omitempty"` // Optional, for authentication
}

func (c *Client) AssignServiceRoleToServiceAccount(ctx context.Context, input AssignServiceRoleToServiceAccountInput) (*ServiceAccount, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/assign-service-role", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input.ApiKey != "" {
		req.Header.Set("X-Api-Key", input.ApiKey)
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
	var updatedServiceAccount ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&updatedServiceAccount); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedServiceAccount, nil
}

func (c *Client) RemoveServiceRoleFromServiceAccount(ctx context.Context, serviceAccountID uuid.UUID, serviceRoleID uuid.UUID) error {
	// Construct the URL for the request
	url := fmt.Sprintf("%s/service-account/%s/role/%s", c.BaseURL, serviceAccountID, serviceRoleID)

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// If you need to set additional headers, such as authentication, do that here

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

// ge-auth/pkg/clientlib/authlib/service_accounts.go
func (c *Client) GetServiceRolesByServiceAccountIDInServiceAccountModel(ctx context.Context, serviceAccountID uuid.UUID) ([]uuid.UUID, error) {
	// Construct the URL with serviceAccountID
	url := fmt.Sprintf("%s/get-service-roles/%s", c.BaseURL, serviceAccountID.String())

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
	var serviceRoleIDs []uuid.UUID
	if err := json.NewDecoder(resp.Body).Decode(&serviceRoleIDs); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return serviceRoleIDs, nil
}

func (c *Client) GetServiceAccountsByServiceRoleID(ctx context.Context, serviceRoleID uuid.UUID) ([]ServiceAccount, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-accounts-by-service-role-id/"+serviceRoleID.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the appropriate headers if needed
	// e.g., req.Header.Set("Authorization", "Bearer "+token)

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
	var serviceAccounts []ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&serviceAccounts); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return serviceAccounts, nil
}

type GetRolesForServiceAccountInput struct {
	ServiceAccountID uuid.UUID `json:"service_account_id"`
	ApiKey           string    `json:"api_key,omitempty"` // Optional, if you want to include an ApiKey
}

func (c *Client) GetRolesForServiceAccount(ctx context.Context, input GetRolesForServiceAccountInput) ([]string, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/get-roles-for-service-account?serviceAccountID=%s", c.BaseURL, input.ServiceAccountID.String()), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input.ApiKey != "" {
		req.Header.Set("X-Api-Key", input.ApiKey)
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
	var serviceRoles []string
	if err := json.NewDecoder(resp.Body).Decode(&serviceRoles); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return serviceRoles, nil
}

type IsServiceRoleAssignedToServiceAccountInput struct {
	ServiceRoleID    uuid.UUID `json:"service_role_id"`
	ServiceAccountID uuid.UUID `json:"service_account_id"`
}

func (c *Client) IsServiceRoleAssignedToServiceAccount(ctx context.Context, input IsServiceRoleAssignedToServiceAccountInput) (bool, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return false, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-role-assignment", bytes.NewBuffer(requestBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return false, fmt.Errorf("failed to decode error response: %w", err)
		}
		return false, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var response struct {
		IsAssigned bool `json:"IsAssigned"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return response.IsAssigned, nil
}
