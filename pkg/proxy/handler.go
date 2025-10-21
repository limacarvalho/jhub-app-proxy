// Package proxy provides HTTP reverse proxying to backend applications
//
// This package is responsible ONLY for forwarding requests to the backend application.
// It does not handle interim pages or logs API - those are handled by the routing layer in main.
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/nebari-dev/jhub-app-proxy/pkg/auth"
	"github.com/nebari-dev/jhub-app-proxy/pkg/logger"
	"github.com/nebari-dev/jhub-app-proxy/pkg/process"
)

// Handler forwards HTTP requests to the backend application
type Handler struct {
	manager       *process.ManagerWithLogs
	upstreamURL   string
	reverseProxy  *httputil.ReverseProxy
	logger        *logger.Logger
	authType      string
	oauthMW       *auth.OAuthMiddleware
	progressive   bool
	servicePrefix string // JupyterHub service prefix
	stripPrefix   bool   // Whether to strip prefix before forwarding (default: true)
}

// NewHandler creates a new proxy handler
func NewHandler(manager *process.ManagerWithLogs, upstreamURL string, authType string, progressive bool, servicePrefix string, stripPrefix bool, log *logger.Logger) (*Handler, error) {
	target, _ := url.Parse(upstreamURL)

	var oauthMW *auth.OAuthMiddleware
	if authType == "oauth" {
		var err error
		oauthMW, err = auth.NewOAuthMiddleware(log)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth middleware: %w", err)
		}
	}

	h := &Handler{
		manager:       manager,
		upstreamURL:   upstreamURL,
		logger:        log,
		authType:      authType,
		oauthMW:       oauthMW,
		progressive:   progressive,
		servicePrefix: servicePrefix,
		stripPrefix:   stripPrefix,
	}

	// Configure reverse proxy
	if progressive {
		// For progressive mode, use custom transport with flushing
		h.reverseProxy = httputil.NewSingleHostReverseProxy(target)
		h.reverseProxy.FlushInterval = -1 // Flush immediately on each write
	} else {
		h.reverseProxy = httputil.NewSingleHostReverseProxy(target)
	}

	return h, nil
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := http.HandlerFunc(h.serve)

	// Wrap with OAuth if enabled
	if h.oauthMW != nil {
		h.oauthMW.Wrap(handler).ServeHTTP(w, r)
	} else {
		handler.ServeHTTP(w, r)
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	originalPath := r.URL.Path
	forwardPath := originalPath

	// Log incoming request details (header names only at INFO level)
	h.logger.Info("incoming request",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"remote_addr", r.RemoteAddr,
		"header_names", extractHeaderNames(r.Header))

	// Log full headers at DEBUG level
	h.logger.Debug("incoming request headers",
		"headers", r.Header)

	// Create response writer wrapper to capture response details
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Strip prefix if configured (default for most apps like Streamlit, Voila, etc.)
	// Don't strip for apps like JupyterLab that are configured with ServerApp.base_url
	if h.stripPrefix && h.servicePrefix != "" {
		// Strip the service prefix from the path
		// e.g., /user/admin/custom-py/index.html -> /index.html
		if len(originalPath) > len(h.servicePrefix) {
			forwardPath = originalPath[len(h.servicePrefix):]
		} else if originalPath == h.servicePrefix {
			forwardPath = "/"
		}

		// Create new request with stripped path
		newReq := r.Clone(r.Context())
		newReq.URL.Path = forwardPath

		backendURL := h.upstreamURL + forwardPath
		h.logger.Info("proxying request to backend (prefix stripped)",
			"original_path", originalPath,
			"forwarded_path", forwardPath,
			"backend_url", backendURL,
			"service_prefix", h.servicePrefix,
			"method", r.Method)

		h.reverseProxy.ServeHTTP(rw, newReq)
	} else {
		// Forward as-is (for apps configured with base_url like JupyterLab)
		backendURL := h.upstreamURL + originalPath
		h.logger.Info("proxying request to backend (no stripping)",
			"path", originalPath,
			"backend_url", backendURL,
			"strip_prefix", h.stripPrefix,
			"method", r.Method)

		h.reverseProxy.ServeHTTP(rw, r)
	}

	// Log response details (header names only at INFO level)
	h.logger.Info("response sent to client",
		"status_code", rw.statusCode,
		"header_names", extractHeaderNames(rw.Header()))

	// Log full response headers at DEBUG level
	h.logger.Debug("response headers",
		"headers", rw.Header())
}

// extractHeaderNames returns a slice of header names from an http.Header map
func extractHeaderNames(headers http.Header) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return names
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}
