// sg-auth/pkg/clientlib/authlib/service_roles.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type ServiceRole struct {
	ID          uuid.UUID           `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Permissions []ServicePermission `json:"permissions"`
}

type CreateServiceRoleInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ServiceRolesResponse struct {
	ServiceRoles []ServiceRole `json:"service_roles"`
}

// Error types
var (
	ErrInvalidInputData                   = errors.New("invalid input data")
	ErrInvalidSecretID                    = errors.New("invalid secret ID")
	ErrInvalidSecretValue                 = errors.New("invalid secret value")
	ErrInvalidProjectID                   = errors.New("invalid project ID")
	ErrFailedToCreateSecretManagerClient  = errors.New("failed to create secret manager client")
	ErrFailedToGetSecret                  = errors.New("failed to get secret")
	ErrFailedToAuthenticateServiceAccount = errors.New("failed to authenticate service account")
	ErrNotFound                           = errors.New("not found")
)

func (c *Client) CreateServiceRole(ctx context.Context, input CreateServiceRoleInput) (*ServiceRole, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-roles", bytes.NewBuffer(requestBody))
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
	var newServiceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&newServiceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &newServiceRole, nil
}

func (c *Client) GetServiceRoleByID(ctx context.Context, id uuid.UUID) (*ServiceRole, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, id.String())

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
	var serviceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&serviceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceRole, nil
}

func (c *Client) GetServiceRoleByName(ctx context.Context, name string) (*ServiceRole, error) {
	// Construct the URL with the service role name
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, name)

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
	var serviceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&serviceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &serviceRole, nil
}

func (c *Client) GetServiceRoleIDByName(ctx context.Context, name string) (*uuid.UUID, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-roles/"+name, nil)
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
	var response struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &response.ID, nil
}

type UpdateServiceRoleInput struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

func (c *Client) UpdateServiceRole(ctx context.Context, input UpdateServiceRoleInput) (*ServiceRole, error) {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	url := fmt.Sprintf("%s/service-roles/%s", c.BaseURL, input.ID)
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
	var updatedServiceRole ServiceRole
	if err := json.NewDecoder(resp.Body).Decode(&updatedServiceRole); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedServiceRole, nil
}

func (c *Client) DeleteServiceRole(ctx context.Context, roleID uuid.UUID) error {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/service-roles/"+roleID.String(), nil)
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

// ListServiceRolesOutput is the response structure for listing service roles
type ListServiceRolesOutput struct {
	ServiceRoles []ServiceRole `json:"service_roles"`
}

func (c *Client) ListServiceRoles(ctx context.Context) (*ListServiceRolesOutput, error) {
	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/service-roles", nil)
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
	var output ListServiceRolesOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &output, nil
}

type AssignServicePermissionInput struct {
	ServiceRoleID       uuid.UUID `json:"service_role_id"`
	ServicePermissionID uuid.UUID `json:"service_permission_id"`
}

func (c *Client) AssignServicePermissionToServiceRole(ctx context.Context, input AssignServicePermissionInput) error {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/assign-service-permission", bytes.NewBuffer(requestBody))
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

type RemoveServicePermissionInput struct {
	ServiceRoleID       uuid.UUID `json:"service_role_id"`
	ServicePermissionID uuid.UUID `json:"service_permission_id"`
}

func (c *Client) RemoveServicePermissionFromServiceRole(ctx context.Context, input RemoveServicePermissionInput) error {
	// JSON encode the input
	requestBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/remove-service-permission", bytes.NewBuffer(requestBody))
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

func (c *Client) DoesServiceRoleExist(ctx context.Context, id uuid.UUID) (bool, error) {
	// Call GetServiceRoleByID to check if the service role exists
	_, err := c.GetServiceRoleByID(ctx, id)

	// If the error is not nil, it means the service role doesn't exist
	if err != nil {
		// Check if the error is due to the service role not found
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		// Return the error if it's not a not found error
		return false, err
	}

	// If no error occurred, the service role exists
	return true, nil
}

func (c *Client) GetServiceRolesByServiceAccountIDInServiceRoleModel(ctx context.Context, serviceAccountID uuid.UUID) ([]ServiceRole, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles?service_account_id=%s", c.BaseURL, serviceAccountID.String())

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
	var rolesResponse ServiceRolesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rolesResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return rolesResponse.ServiceRoles, nil
}

func (c *Client) GetServicePermissionsByServiceRoleIDInServiceRoleServicePermissionsModel(ctx context.Context, serviceRoleID uuid.UUID) ([]ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles/%s/service-permissions", c.BaseURL, serviceRoleID.String())

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
	var permissionsResponse ServicePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&permissionsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return permissionsResponse.ServicePermissions, nil
}

func (c *Client) GetServiceRolesByServicePermissionID(ctx context.Context, servicePermissionID uuid.UUID) ([]ServiceRole, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles?service_permission_id=%s", c.BaseURL, servicePermissionID.String())

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
	var rolesResponse ServiceRolesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rolesResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return rolesResponse.ServiceRoles, nil
}

func (c *Client) IsServicePermissionAssignedToServiceRole(ctx context.Context, serviceRoleID, servicePermissionID uuid.UUID) (bool, error) {
	// Get the service role by ID
	serviceRole, err := c.GetServiceRoleByID(ctx, serviceRoleID)
	if err != nil {
		return false, err
	}

	// Check if the service permission is assigned to the service role
	for _, permission := range serviceRole.Permissions {
		if permission.ID == servicePermissionID {
			return true, nil
		}
	}

	// If the service permission is not found in the service role's permissions, return false
	return false, nil
}
