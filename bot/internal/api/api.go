package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/pranavagiligar/the_switch_bot/internal/config"
	"github.com/pranavagiligar/the_switch_bot/internal/models"
)

type Client struct {
	httpClient *http.Client
	cfg        *config.Config
	jwtToken   string
	tokenMutex sync.RWMutex
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cfg:        cfg,
	}
}

// Authenticate attempts to get a new JWT token from the API
func (c *Client) Authenticate() error {
	log.Println("[AUTH] Attempting to authenticate with Job Manager API...")

	payload := map[string]string{
		"username": c.cfg.DefaultUsername,
		"password": c.cfg.DefaultPassword,
	}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", c.cfg.APIBaseURL+"/login", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errRes map[string]string
		json.NewDecoder(resp.Body).Decode(&errRes)
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, errRes["error"])
	}

	var authResponse models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	c.tokenMutex.Lock()
	c.jwtToken = authResponse.Token
	c.tokenMutex.Unlock()
	log.Println("[AUTH] Successfully authenticated. Token obtained.")
	return nil
}

// refreshAuth ensures the JWT is available and valid (by trying to refresh if needed)
func (c *Client) refreshAuth() error {
	c.tokenMutex.RLock()
	tokenExists := c.jwtToken != ""
	c.tokenMutex.RUnlock()

	if !tokenExists {
		return c.Authenticate()
	}
	return nil
}

// Call performs an authenticated call to the job manager API
func (c *Client) Call(method, path string, body io.Reader) (*http.Response, error) {
	// Ensure authentication is fresh
	if err := c.refreshAuth(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	url := c.cfg.APIBaseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	c.tokenMutex.RLock()
	req.Header.Set("Authorization", "Bearer "+c.jwtToken)
	c.tokenMutex.RUnlock()

	resp, err := c.httpClient.Do(req)

	// If 401, clear the token and try again once (recursive call, limited depth)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		log.Println("[AUTH] Token expired, attempting re-authentication...")
		c.tokenMutex.Lock()
		c.jwtToken = "" // Clear invalid token
		c.tokenMutex.Unlock()
		if err := c.Authenticate(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		// Second attempt after re-authentication
		req.Header.Set("Authorization", "Bearer "+c.jwtToken)
		return c.httpClient.Do(req)
	}

	return resp, err
}
