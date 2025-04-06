package traefik_lambdaauthorizer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Config struct {
	AuthorizerURL  string `json:"authorizerUrl,omitempty"`
	IdentityHeader string `json:"identityHeader,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IdentityHeader: "x-session-id",
	}
}

type LambdaAuthorizer struct {
	next           http.Handler
	authorizerURL  string
	identityHeader string
	name           string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.AuthorizerURL == "" {
		return nil, fmt.Errorf("authorizerUrl must be specified")
	}

	return &LambdaAuthorizer{
		next:           next,
		authorizerURL:  config.AuthorizerURL,
		identityHeader: config.IdentityHeader,
		name:           name,
	}, nil
}

func (m *LambdaAuthorizer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check for required x-session-id header
	identityValue := req.Header.Get(m.identityHeader)
	if identityValue == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("Unauthorized"))
		return
	}

	// Read transformed request body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	// Parse JSON
	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(rw, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Set identity source in payload
	payload["identitySource"] = []string{identityValue}

	// Call the authorizer
	authReq, err := http.NewRequest("POST", m.authorizerURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(rw, "Failed to create authorizer request", http.StatusInternalServerError)
		return
	}
	authReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	authResp, err := client.Do(authReq)
	if err != nil {
		http.Error(rw, "Authorizer unreachable", http.StatusInternalServerError)
		return
	}
	defer authResp.Body.Close()

	respBody, err := io.ReadAll(authResp.Body)
	if err != nil {
		http.Error(rw, "Failed to read authorizer response", http.StatusInternalServerError)
		return
	}

	var authResult struct {
		IsAuthorized bool                   `json:"isAuthorized"`
		Context      map[string]interface{} `json:"context"`
	}
	if err := json.Unmarshal(respBody, &authResult); err != nil {
		http.Error(rw, "Invalid authorizer response", http.StatusInternalServerError)
		return
	}

	if !authResult.IsAuthorized {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"error": "Unauthorized"}`))
		return
	}

	// Inject into requestContext.authorizer.lambda
	requestContext, ok := payload["requestContext"].(map[string]interface{})
	if !ok {
		requestContext = map[string]interface{}{}
	}
	authWrapper := map[string]interface{}{
		"lambda": authResult.Context,
	}
	requestContext["authorizer"] = authWrapper
	payload["requestContext"] = requestContext

	// Replace body with new payload
	updatedBody, err := json.Marshal(payload)
	if err != nil {
		http.Error(rw, "Failed to encode updated payload", http.StatusInternalServerError)
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(updatedBody))
	req.ContentLength = int64(len(updatedBody))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))

	m.next.ServeHTTP(rw, req)
}
