package clouddirector

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// BearerTokenAuth manages the exchange of the IAM token -> Cloud Director access token.
type BearerTokenAuth struct {
	BearerToken string
	Log         *slog.Logger
}

const (
	loginSessionPath = "/cloudapi/1.0.0/sessions"
	tokenHeaderName  = "X-VMWARE-VCLOUD-ACCESS-TOKEN" // header returned by VCD with the bearer token
)

type BearerTokenAuthOptions struct {
	BaseURL  string
	Org      string
	Version  string
	IAMToken string
	Log      slog.Logger
}

// NewBearerTokenAuth creates the instance, requests the token from VCD, and validates the result.
func NewBearerTokenAuth(options *BearerTokenAuthOptions) (*BearerTokenAuth, error) {
	if options.IAMToken == "" {
		return nil, errors.New("IAM token cannot be empty")
	}
	if options.BaseURL == "" {
		return nil, errors.New("BaseURL cannot be empty")
	}
	if options.Org == "" {
		return nil, errors.New("Org cannot be empty")
	}

	bearerTokenAuth := &BearerTokenAuth{
		Log: options.Log.With("service", "bearer-token-auth"),
	}

	_, err := bearerTokenAuth.SaveTokenInfo(options)
	if err != nil {
		return nil, err
	}
	bearerTokenAuth.Log.Info("BearerTokenAuth created successfully")
	return bearerTokenAuth, nil
}

// Authenticate adds the Authorisation header to the HTTP request.
func (authenticator *BearerTokenAuth) Authenticate(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authenticator.BearerToken))
	authenticator.Log.Debug("Authenticated outbound request", slog.String("type", "bearerToken"))
}

// RequestToken performs a POST to /cloudapi/1.0.0/sessions with the required headers.
func (authenticator *BearerTokenAuth) SaveTokenInfo(options *BearerTokenAuthOptions) (*http.Response, error) {
	requestURL := options.BaseURL + loginSessionPath

	req, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	// Required headers (Accept + Authorization containing IAM token + org).
	req.Header.Set("Accept", fmt.Sprintf("application/*;version=%s", options.Version))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s; org=%s", options.IAMToken, options.Org))

	client := &http.Client{Timeout: 60 * time.Second}
	authenticator.Log.Info("Send token request to", slog.String("url", requestURL))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w\nURL: %s\nSuggestion: Check network connectivity and VCD endpoint", err, requestURL)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("token exchange failed with status %d\nURL: %s\nResponse: %s\nSuggestion: Verify IBM_APIKEY is valid and has access to organization %q",
			resp.StatusCode, requestURL, string(bodyBytes), options.Org)
	}

	// extracts the bearer token from the X-VMWARE-VCLOUD-ACCESS-TOKEN header.
	authenticator.BearerToken = resp.Header.Get(tokenHeaderName)

	if authenticator.BearerToken == "" {
		return nil, fmt.Errorf("bearer token not found in response headers\nExpected header: %s\nReceived headers: %v\nSuggestion: Check VCD API version compatibility",
			tokenHeaderName, resp.Header)
	}

	authenticator.Log.Info("Token response received")
	return resp, nil
}
