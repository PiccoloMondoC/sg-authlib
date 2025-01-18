// sg-auth/pkg/clientlib/authlib/service_permissions.go
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

type ServicePermission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type ServicePermissionsResponse struct {
	ServicePermissions []ServicePermission `json:"service_permissions"`
}

func (c *Client) CreateServicePermission(ctx context.Context, name, description string) (*ServicePermission, error) {
	// Prepare the request body
	input := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{
		Name:        name,
		Description: description,
	}
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/service-permissions", bytes.NewBuffer(requestBody))
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
	var newServicePermission ServicePermission
	if err := json.NewDecoder(resp.Body).Decode(&newServicePermission); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &newServicePermission, nil
}

func (c *Client) GetServicePermissionByID(ctx context.Context, id uuid.UUID) (*ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions/%s", c.BaseURL, id.String())

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
	var servicePermission ServicePermission
	if err := json.NewDecoder(resp.Body).Decode(&servicePermission); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &servicePermission, nil
}

func (c *Client) GetServicePermissionByName(ctx context.Context, name string) (*ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions?name=%s", c.BaseURL, name)

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
	var servicePermission ServicePermission
	if err := json.NewDecoder(resp.Body).Decode(&servicePermission); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &servicePermission, nil
}

func (c *Client) UpdateServicePermission(ctx context.Context, id uuid.UUID, name, description string) (*ServicePermission, error) {
	// Prepare the request body
	input := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{
		Name:        name,
		Description: description,
	}
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions/%s", c.BaseURL, id.String())

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
	var updatedServicePermission ServicePermission
	if err := json.NewDecoder(resp.Body).Decode(&updatedServicePermission); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return &updatedServicePermission, nil
}

func (c *Client) DeleteServicePermission(ctx context.Context, id uuid.UUID) error {
	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions/%s", c.BaseURL, id.String())

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
	if resp.StatusCode != http.StatusNoContent {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		return errors.New(errorResponse.Message)
	}

	return nil
}

func (c *Client) ListServicePermissions(ctx context.Context) ([]ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions", c.BaseURL)

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
	var servicePermissionsResponse ServicePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&servicePermissionsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return servicePermissionsResponse.ServicePermissions, nil
}

func (c *Client) DoesServicePermissionExist(ctx context.Context, name string) (bool, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-permissions?name=%s", c.BaseURL, name)

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
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return false, fmt.Errorf("failed to decode error response: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, errors.New(errorResponse.Message)
	}

	// Decode the successful response
	var servicePermissionsResponse ServicePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&servicePermissionsResponse); err != nil {
		return false, fmt.Errorf("failed to decode successful response: %w", err)
	}

	// Check if the service permission exists
	for _, permission := range servicePermissionsResponse.ServicePermissions {
		if permission.Name == name {
			return true, nil
		}
	}

	return false, nil
}

func (c *Client) GetServicePermissionsByServiceID(ctx context.Context, serviceID uuid.UUID) ([]ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/services/%s/permissions", c.BaseURL, serviceID.String())

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
	var servicePermissionsResponse ServicePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&servicePermissionsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return servicePermissionsResponse.ServicePermissions, nil
}

func (c *Client) GetServicePermissionsByServiceRoleIDInServicePermissionModel(ctx context.Context, serviceRoleID uuid.UUID) ([]ServicePermission, error) {
	// Construct the URL
	url := fmt.Sprintf("%s/service-roles/%s/permissions", c.BaseURL, serviceRoleID.String())

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
	var servicePermissionsResponse ServicePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&servicePermissionsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode successful response: %w", err)
	}

	return servicePermissionsResponse.ServicePermissions, nil
}
