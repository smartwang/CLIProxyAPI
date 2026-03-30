package management

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// StartAutoAuthMaintainer starts a background goroutine to periodically check and clean auth credentials.
func (h *Handler) StartAutoAuthMaintainer(ctx context.Context) {
	if h == nil || h.cfg == nil || !h.cfg.AutoCleanAuth.Enable {
		return
	}

	interval := time.Duration(h.cfg.AutoCleanAuth.IntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	ticker := time.NewTicker(interval)
	
	// Run an initial cycle shortly after startup to clean up any immediate issues.
	go func() {
		time.Sleep(15 * time.Second)
		h.runAutoCleanCycle(ctx)
	}()

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runAutoCleanCycle(ctx)
			}
		}
	}()
}

func (h *Handler) runAutoCleanCycle(ctx context.Context) {
	if h.authManager == nil || h.cfg == nil || !h.cfg.AutoCleanAuth.Enable {
		log.Debug("AutoClean: skipped cycle (disabled, missing config, or authManager nil)")
		return
	}

	auths := h.authManager.List()
	if len(auths) == 0 {
		return
	}

	log.Infof("AutoClean: starting cycle, verifying %d credentials. Concurrency: %d", len(auths), h.cfg.AutoCleanAuth.MaxConcurrency)

	concurrency := h.cfg.AutoCleanAuth.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	errorKeywords := h.cfg.AutoCleanAuth.ErrorKeywords

	for _, authItem := range auths {
		if authItem == nil {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(auth *coreauth.Auth) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1. Perform health check/refresh logic for providers
			var refreshErr error

			// Since resolveTokenForAuth already abstracts calling the correct refresh methods:
			// (e.g., refreshGeminiOAuthAccessToken or others) we just use it directly.
			token, refreshErr := h.resolveTokenForAuth(ctx, auth)

			latestAuth, _ := h.authManager.GetByID(auth.ID)
			if latestAuth == nil {
				latestAuth = auth
			}

			// Proactive Network Health Ping
			if refreshErr == nil {
				// Perform the ping! Even if it was an error, we can attempt recovery.
				refreshErr = h.pingAuthForHealthStatus(ctx, latestAuth, token)
			}

			needsUpdate := false

			if refreshErr != nil {
				log.Debugf("AutoClean: health check failed for %s (%s): %v", latestAuth.Index, latestAuth.Provider, refreshErr)
				errMsg := refreshErr.Error()
				if !strings.EqualFold(string(latestAuth.Status), string(coreauth.StatusError)) || latestAuth.StatusMessage != errMsg {
					latestAuth.Status = coreauth.StatusError
					latestAuth.StatusMessage = errMsg
					needsUpdate = true
				}
			} else {
				// Health check succeeded!
				if strings.EqualFold(string(latestAuth.Status), string(coreauth.StatusError)) || latestAuth.StatusMessage != "" {
					latestAuth.Status = "active"
					latestAuth.StatusMessage = ""
					latestAuth.LastError = nil
					needsUpdate = true
				}
				now := time.Now().UTC()
				if now.Sub(latestAuth.LastRefreshedAt) > time.Minute {
					latestAuth.LastRefreshedAt = now
					needsUpdate = true
				}
			}

			if needsUpdate {
				_, _ = h.authManager.Update(ctx, latestAuth)
				_ = h.upsertAuthRecord(ctx, latestAuth)
			}

			if latestAuth == nil {
				return
			}

			status := strings.ToLower(strings.TrimSpace(string(latestAuth.Status)))
			if status != "error" {
				return
			}
			msg := strings.ToLower(latestAuth.StatusMessage)

			// 2. Check if we need to clean/backup based on keywords
			shouldClean := false
			problemType := "auto_cleaned_error"

			if len(errorKeywords) == 0 {
				shouldClean = true
			} else {
				for _, kw := range errorKeywords {
					if kw != "" && strings.Contains(msg, strings.ToLower(kw)) {
						shouldClean = true
						problemType = kw
						break
					}
				}
			}

			if shouldClean {
				_, _, err := h.safeBackupAndDelete(ctx, latestAuth, problemType)
				if err != nil {
					log.Errorf("Auto-clean failed to backup and delete auth %s: %v", latestAuth.Index, err)
				} else {
					log.Infof("Auto-cleaned auth %s due to error matching: %v", latestAuth.Index, problemType)
				}
			}

		}(authItem)
	}

	wg.Wait()
}

func (h *Handler) pingAuthForHealthStatus(ctx context.Context, auth *coreauth.Auth, token string) error {
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))

	if provider == "" || token == "" {
		return nil
	}

	reqURL := ""
	method := "GET"
	var headers map[string]string

	switch provider {
	case "codex", "openai-compat", "openai":
		reqURL = "https://api.openai.com/v1/models"
		if auth.Attributes != nil && auth.Attributes["base_url"] != "" {
			reqURL = strings.TrimRight(strings.TrimSpace(auth.Attributes["base_url"]), "/") + "/v1/models"
		}
		headers = map[string]string{
			"Authorization": "Bearer " + token,
		}
	case "claude", "anthropic":
		reqURL = "https://api.anthropic.com/v1/models"
		if auth.Attributes != nil && auth.Attributes["base_url"] != "" {
			reqURL = strings.TrimRight(strings.TrimSpace(auth.Attributes["base_url"]), "/") + "/v1/models"
		}
		headers = map[string]string{
			"x-api-key":         token,
			"anthropic-version": "2023-06-01",
		}
	case "gemini", "gemini-cli":
		reqURL = "https://generativelanguage.googleapis.com/v1beta/models"
		if auth.Attributes != nil && auth.Attributes["base_url"] != "" {
			reqURL = strings.TrimRight(strings.TrimSpace(auth.Attributes["base_url"]), "/") + "/v1beta/models"
		}
		headers = map[string]string{
			"Authorization": "Bearer " + token,
		}
		if !strings.HasPrefix(token, "ya29") && len(token) < 100 {
			reqURL = reqURL + "?key=" + token
			delete(headers, "Authorization")
		}
	default:
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if auth.ProxyURL != "" {
		if pu, err := url.Parse(auth.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		rawBody := strings.TrimSpace(string(bodyBytes))
		lowerErr := strings.ToLower(rawBody)

		// For restricted API keys that cannot access /v1/models, the fact that we received
		// this domain-specific error implies the API key is otherwise structurally valid and authenticated.
		// We consider it a "success" (nil error) so it stays Active in the panel.
		if resp.StatusCode == 403 && (strings.Contains(lowerErr, "missing scopes") || strings.Contains(lowerErr, "api.model.read") || strings.Contains(lowerErr, "role in your organization")) {
			return nil
		}

		if rawBody == "" {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		// Return the raw JSON block as requested by user to help them infer error-keywords
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, rawBody)
	}

	return nil
}
