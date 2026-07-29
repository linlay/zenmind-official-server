package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	googleIssuer   = "https://accounts.google.com"
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
)

var ErrGoogleNotConfigured = errors.New("google oauth is not configured")

type GoogleIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

type GoogleProvider interface {
	Configured() bool
	AuthCodeURL(state, nonce, codeChallenge string) string
	ExchangeCode(ctx context.Context, code, codeVerifier, nonce string) (GoogleIdentity, error)
	VerifyIDToken(ctx context.Context, rawToken string) (GoogleIdentity, error)
}

type disabledGoogleProvider struct{}

func (disabledGoogleProvider) Configured() bool {
	return false
}

func (disabledGoogleProvider) AuthCodeURL(string, string, string) string {
	return ""
}

func (disabledGoogleProvider) ExchangeCode(context.Context, string, string, string) (GoogleIdentity, error) {
	return GoogleIdentity{}, ErrGoogleNotConfigured
}

func (disabledGoogleProvider) VerifyIDToken(context.Context, string) (GoogleIdentity, error) {
	return GoogleIdentity{}, ErrGoogleNotConfigured
}

type GoogleProviderConfig struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	DesktopClientID string
}

func NewGoogleProvider(cfg GoogleProviderConfig) GoogleProvider {
	clientID := strings.TrimSpace(cfg.ClientID)
	clientSecret := strings.TrimSpace(cfg.ClientSecret)
	redirectURL := strings.TrimSpace(cfg.RedirectURL)
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return disabledGoogleProvider{}
	}

	keySet := oidc.NewRemoteKeySet(context.Background(), googleJWKSURL)
	return &liveGoogleProvider{
		oauthConfig: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  googleAuthURL,
				TokenURL: googleTokenURL,
			},
			Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		webVerifier:      oidc.NewVerifier(googleIssuer, keySet, &oidc.Config{ClientID: clientID}),
		desktopVerifiers: newGoogleVerifiers(keySet, googleAudiences(cfg.DesktopClientID)),
	}
}

type liveGoogleProvider struct {
	oauthConfig      oauth2.Config
	webVerifier      *oidc.IDTokenVerifier
	desktopVerifiers []*oidc.IDTokenVerifier
}

func (p *liveGoogleProvider) Configured() bool {
	return p != nil && p.oauthConfig.ClientID != "" && p.oauthConfig.ClientSecret != "" && p.oauthConfig.RedirectURL != ""
}

func (p *liveGoogleProvider) AuthCodeURL(state, nonce, codeChallenge string) string {
	return p.oauthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
	)
}

func (p *liveGoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier, nonce string) (GoogleIdentity, error) {
	token, err := p.oauthConfig.Exchange(
		ctx,
		strings.TrimSpace(code),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return GoogleIdentity{}, fmt.Errorf("exchange google auth code: %w", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if strings.TrimSpace(rawIDToken) == "" {
		return GoogleIdentity{}, errors.New("google response did not include id_token")
	}
	return verifyGoogleIDToken(ctx, rawIDToken, nonce, []*oidc.IDTokenVerifier{p.webVerifier})
}

func (p *liveGoogleProvider) VerifyIDToken(ctx context.Context, rawToken string) (GoogleIdentity, error) {
	if len(p.desktopVerifiers) == 0 {
		return GoogleIdentity{}, errors.New("google desktop client id is not configured")
	}
	return verifyGoogleIDToken(ctx, rawToken, "", p.desktopVerifiers)
}

func verifyGoogleIDToken(
	ctx context.Context,
	rawToken, expectedNonce string,
	verifiers []*oidc.IDTokenVerifier,
) (GoogleIdentity, error) {
	var lastErr error
	for _, verifier := range verifiers {
		if verifier == nil {
			continue
		}
		idToken, err := verifier.Verify(ctx, strings.TrimSpace(rawToken))
		if err != nil {
			lastErr = err
			continue
		}
		if expectedNonce != "" && idToken.Nonce != expectedNonce {
			return GoogleIdentity{}, errors.New("google id token nonce mismatch")
		}

		var claims struct {
			Subject       string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Picture       string `json:"picture"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return GoogleIdentity{}, fmt.Errorf("decode google id token claims: %w", err)
		}
		if strings.TrimSpace(claims.Subject) == "" {
			return GoogleIdentity{}, errors.New("google id token subject is missing")
		}
		if !claims.EmailVerified || !validEmail(claims.Email) {
			return GoogleIdentity{}, errors.New("google account email is not verified")
		}
		return GoogleIdentity{
			Subject:       strings.TrimSpace(claims.Subject),
			Email:         normalizeEmail(claims.Email),
			EmailVerified: true,
			Name:          strings.TrimSpace(claims.Name),
			Picture:       strings.TrimSpace(claims.Picture),
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("google id token audience mismatch")
	}
	return GoogleIdentity{}, fmt.Errorf("verify google id token: %w", lastErr)
}

func newGoogleVerifiers(keySet oidc.KeySet, audiences []string) []*oidc.IDTokenVerifier {
	verifiers := make([]*oidc.IDTokenVerifier, 0, len(audiences))
	for _, audience := range audiences {
		verifiers = append(verifiers, oidc.NewVerifier(googleIssuer, keySet, &oidc.Config{ClientID: audience}))
	}
	return verifiers
}

func googleAudiences(clientIDs ...string) []string {
	audiences := make([]string, 0, len(clientIDs))
	seen := map[string]bool{}
	for _, clientID := range clientIDs {
		clientID = strings.TrimSpace(clientID)
		if clientID == "" || seen[clientID] {
			continue
		}
		audiences = append(audiences, clientID)
		seen[clientID] = true
	}
	return audiences
}
