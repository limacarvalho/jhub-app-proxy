// Package auth provides JupyterHub OAuth authentication
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/nebari-dev/jhub-app-proxy/pkg/logger"
)

// OAuthMiddleware handles JupyterHub OAuth authentication
type OAuthMiddleware struct {
	clientID     string
	apiToken     string
	apiURL       string
	baseURL      string
	hubHost      string
	hubPrefix    string
	cookieName   string
	callbackPath string // Custom callback path (e.g., "oauth_callback" or "_temp/jhub-app-proxy/oauth_callback")
	logger       *logger.Logger
}

// NewOAuthMiddleware creates a new OAuth middleware with default callback path
func NewOAuthMiddleware(log *logger.Logger) (*OAuthMiddleware, error) {
	return NewOAuthMiddlewareWithCallbackPath(log, "oauth_callback")
}

// NewOAuthMiddlewareWithCallbackPath creates a new OAuth middleware with a custom callback path
func NewOAuthMiddlewareWithCallbackPath(log *logger.Logger, callbackPath string) (*OAuthMiddleware, error) {
	apiURL := os.Getenv("JUPYTERHUB_API_URL")
	if apiURL == "" {
		return nil, fmt.Errorf("JUPYTERHUB_API_URL not set")
	}

	apiToken := os.Getenv("JUPYTERHUB_API_TOKEN")
	if apiToken == "" {
		return nil, fmt.Errorf("JUPYTERHUB_API_TOKEN not set")
	}

	clientID := os.Getenv("JUPYTERHUB_CLIENT_ID")
	if clientID == "" {
		clientID = os.Getenv("JUPYTERHUB_SERVICE_PREFIX")
	}

	baseURL := os.Getenv("JUPYTERHUB_SERVICE_PREFIX")
	if baseURL == "" {
		baseURL = "/"
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	hubHost := os.Getenv("JUPYTERHUB_HOST")
	hubPrefix := os.Getenv("JUPYTERHUB_BASE_URL")
	if hubPrefix == "" {
		hubPrefix = "/hub/"
	}
	// CRITICAL: JUPYTERHUB_BASE_URL can be "/" for custom deployments
	// but OAuth endpoints are ALWAYS at /hub/api/oauth2/...
	// So we need to ensure the OAuth URL includes /hub/ even if base URL is /
	if hubPrefix == "/" {
		hubPrefix = "/hub/"
	}
	if !strings.HasSuffix(hubPrefix, "/") {
		hubPrefix += "/"
	}

	return &OAuthMiddleware{
		clientID:     clientID,
		apiToken:     apiToken,
		apiURL:       apiURL,
		baseURL:      baseURL,
		hubHost:      hubHost,
		hubPrefix:    hubPrefix,
		cookieName:   clientID,
		callbackPath: callbackPath,
		logger:       log.WithComponent("oauth"),
	}, nil
}

// Wrap wraps an HTTP handler with OAuth authentication
func (m *OAuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth callback
		// Check if the path ends with the callback path (e.g., "/oauth_callback" or "/_temp/jhub-app-proxy/oauth_callback")
		if strings.HasSuffix(r.URL.Path, "/"+m.callbackPath) {
			m.handleCallback(w, r)
			return
		}

		// Fast-path for WebSocket upgrades
		// WebSocket upgrade requests need to be processed quickly to avoid blocking the handshake
		// We skip the expensive token validation and just check that a valid token cookie exists
		if isWebSocketUpgrade(r) {
			cookie, err := r.Cookie(m.cookieName)
			if err == nil && cookie.Value != "" {
				// Token exists - trust it for WebSocket upgrades
				// The initial page load already validated the token
				m.logger.Debug("WebSocket upgrade request with valid token cookie", "path", r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}
			// No token cookie - reject the WebSocket
			m.logger.Warn("WebSocket upgrade request without valid token cookie", "path", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Fast-path for interim page API calls
		// The interim page JavaScript polls /api/logs and /api/logs/stats to check app readiness
		// If the user already authenticated to load the HTML page, we can trust subsequent API calls
		// This avoids the expensive token validation on every poll (which happens every 1 second)
		if strings.Contains(r.URL.Path, "/_temp/jhub-app-proxy/api/") {
			cookie, err := r.Cookie(m.cookieName)
			if err == nil && cookie.Value != "" {
				// Cookie exists - trust it for interim page APIs
				// The user already authenticated to load the interim page
				m.logger.Debug("Interim page API call with valid cookie, allowing", "path", r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}
			// No cookie - this shouldn't happen if the page loaded, but reject it
			m.logger.Warn("Interim page API call without valid cookie", "path", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Regular HTTP requests - full validation
		cookie, err := r.Cookie(m.cookieName)
		if err == nil && cookie.Value != "" {
			// Validate token (you could add caching here if needed)
			m.logger.Debug("Validating token for request", "path", r.URL.Path, "method", r.Method)
			if m.validateToken(cookie.Value) {
				m.logger.Debug("Token valid, allowing request", "path", r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}
			m.logger.Warn("Token validation failed, redirecting to OAuth", "path", r.URL.Path)
		} else {
			if err != nil {
				m.logger.Debug("No token cookie found", "path", r.URL.Path, "error", err.Error())
			} else {
				m.logger.Debug("Empty token cookie", "path", r.URL.Path)
			}
		}

		// No valid token, redirect to OAuth
		m.logger.Info("Redirecting to OAuth login", "path", r.URL.Path)
		m.redirectToLogin(w, r)
	})
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func isWebSocketUpgrade(r *http.Request) bool {
	// Check for WebSocket upgrade headers
	// RFC 6455 requires these headers for WebSocket handshake
	upgrade := r.Header.Get("Upgrade")
	connection := r.Header.Get("Connection")

	// Connection header can contain multiple values (e.g., "keep-alive, Upgrade")
	// so we check if "upgrade" is present in the connection header
	hasUpgradeConnection := false
	for _, v := range strings.Split(connection, ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			hasUpgradeConnection = true
			break
		}
	}

	return strings.EqualFold(upgrade, "websocket") && hasUpgradeConnection
}

func (m *OAuthMiddleware) validateToken(token string) bool {
	req, _ := http.NewRequest("GET", m.apiURL+"/user", nil)
	req.Header.Set("Authorization", "token "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		m.logger.Debug("Token validation failed - network error", "error", err.Error())
		return false
	}
	defer resp.Body.Close()

	isValid := resp.StatusCode == http.StatusOK
	if !isValid {
		m.logger.Debug("Token validation failed - invalid status", "status", resp.StatusCode)
	} else {
		m.logger.Debug("Token validation succeeded")
	}

	return isValid
}

func (m *OAuthMiddleware) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Generate random state
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	// Store original URL to redirect back after OAuth
	originalURL := r.URL.RequestURI()

	// Set state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName + "-oauth-state",
		Value:    state,
		Path:     m.baseURL,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Set original URL cookie to redirect back after OAuth
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName + "-oauth-next",
		Value:    originalURL,
		Path:     m.baseURL,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Build OAuth URL with custom callback path
	redirectURI := m.baseURL + m.callbackPath

	// Construct the OAuth authorize URL
	// If hubHost is set (e.g., "https://example.com"), use it as-is
	// If hubHost is empty, use hubPrefix as a relative URL (e.g., "/hub/")
	var authURL string
	if m.hubHost != "" {
		// Absolute URL: https://example.com/hub/api/oauth2/authorize?...
		authURL = fmt.Sprintf("%s%sapi/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
			m.hubHost, m.hubPrefix, url.QueryEscape(m.clientID), url.QueryEscape(redirectURI), url.QueryEscape(state))
	} else {
		// Relative URL: /hub/api/oauth2/authorize?...
		// This ensures the browser resolves it from the root of the domain
		authURL = fmt.Sprintf("%sapi/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
			m.hubPrefix, url.QueryEscape(m.clientID), url.QueryEscape(redirectURI), url.QueryEscape(state))
	}

	// Log at INFO level so it's always visible for debugging
	m.logger.Info("Redirecting to OAuth", "authURL", authURL, "redirectURI", redirectURI)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (m *OAuthMiddleware) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Validate state
	stateCookie, err := r.Cookie(m.cookieName + "-oauth-state")
	if err != nil || stateCookie.Value != state {
		http.Error(w, "Invalid state", http.StatusForbidden)
		return
	}

	// Exchange code for token
	redirectURI := m.baseURL + m.callbackPath
	data := url.Values{}
	data.Set("client_id", m.clientID)
	data.Set("client_secret", m.apiToken)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, _ := http.NewRequest("POST", m.apiURL+"/oauth2/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		m.logger.Error("token exchange failed", fmt.Errorf("status %d: %s", resp.StatusCode, string(body)))
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "Failed to parse token", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   m.cookieName + "-oauth-state",
		Value:  "",
		Path:   m.baseURL,
		MaxAge: -1,
	})

	// Set token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    tokenResp.AccessToken,
		Path:     m.baseURL,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect back to original URL if saved, otherwise to base URL
	redirectURL := m.baseURL
	if nextCookie, err := r.Cookie(m.cookieName + "-oauth-next"); err == nil && nextCookie.Value != "" {
		redirectURL = nextCookie.Value
		// Clear the next URL cookie
		http.SetCookie(w, &http.Cookie{
			Name:   m.cookieName + "-oauth-next",
			Value:  "",
			Path:   m.baseURL,
			MaxAge: -1,
		})
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
