package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const desktopSsoScope = "profile market tunnel kanban im"

var errDesktopJWTNotConfigured = errors.New("desktop SSO JWT signer is not configured")

type DesktopJWTConfig struct {
	PrivateKeyFile string
	PrivateKeyPEM  string
	Issuer         string
	Audiences      []string
	KeyID          string
	TTL            time.Duration
}

type identityJWTSigner struct {
	privateKey *rsa.PrivateKey
	issuer     string
	audiences  []string
	keyID      string
	ttl        time.Duration
	err        error
}

type identityJWTResult struct {
	Token     string
	Issuer    string
	Audiences []string
	Scope     string
	ExpiresAt time.Time
}

type identityClaims struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Picture      string `json:"picture,omitempty"`
	Role         string `json:"role"`
	AuthProvider string `json:"auth_provider"`
	AuthSub      string `json:"auth_sub,omitempty"`
	Scope        string `json:"scope"`
	SessionID    string `json:"sid"`
	jwt.RegisteredClaims
}

func newIdentityJWTSigner(config DesktopJWTConfig) *identityJWTSigner {
	ttl := config.TTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	signer := &identityJWTSigner{
		issuer:    strings.TrimSpace(config.Issuer),
		audiences: normalizeJWTAudiences(config.Audiences),
		keyID:     strings.TrimSpace(config.KeyID),
		ttl:       ttl,
	}
	if signer.keyID == "" {
		signer.keyID = "default"
	}
	key, err := loadJWTPrivateKey(config.PrivateKeyFile, config.PrivateKeyPEM)
	if err != nil {
		signer.err = err
		return signer
	}
	signer.privateKey = key
	return signer
}

func normalizeJWTAudiences(values []string) []string {
	seen := map[string]bool{}
	audiences := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			audiences = append(audiences, part)
		}
	}
	return audiences
}

func loadJWTPrivateKey(filePath, pemValue string) (*rsa.PrivateKey, error) {
	filePath = strings.TrimSpace(filePath)
	pemValue = strings.TrimSpace(pemValue)
	if filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read SSO JWT private key: %w", err)
		}
		return parseJWTPrivateKeyPEM(string(content))
	}
	if pemValue == "" {
		return nil, errDesktopJWTNotConfigured
	}
	return parseJWTPrivateKeyPEM(strings.ReplaceAll(pemValue, `\n`, "\n"))
}

func parseJWTPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(value)))
	if block == nil {
		return nil, errors.New("SSO JWT private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSO JWT private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("SSO JWT private key must be RSA")
	}
	return key, nil
}

func (s *identityJWTSigner) configured() bool {
	return s != nil && s.err == nil && s.privateKey != nil && s.issuer != "" && len(s.audiences) > 0
}

func (s *identityJWTSigner) issue(user User, now time.Time, sessionID string) (identityJWTResult, error) {
	return s.issueWithPolicy(user, now, sessionID, s.audiences, desktopSsoScope, s.ttl)
}

func (s *identityJWTSigner) issueWithPolicy(
	user User,
	now time.Time,
	sessionID string,
	audiences []string,
	scope string,
	ttl time.Duration,
) (identityJWTResult, error) {
	if s == nil || s.err != nil || s.privateKey == nil || s.issuer == "" {
		if s != nil && s.err != nil && !errors.Is(s.err, errDesktopJWTNotConfigured) {
			return identityJWTResult{}, s.err
		}
		return identityJWTResult{}, errDesktopJWTNotConfigured
	}
	audiences = normalizeJWTAudiences(audiences)
	if len(audiences) == 0 || ttl <= 0 {
		return identityJWTResult{}, errDesktopJWTNotConfigured
	}

	now = now.UTC()
	expiresAt := now.Add(ttl)
	jti, err := randomToken()
	if err != nil {
		return identityJWTResult{}, err
	}
	claims := identityClaims{
		UserID:       strconv.FormatInt(user.ID, 10),
		Email:        user.Email,
		Name:         user.DisplayName,
		Picture:      user.AvatarURL,
		Role:         user.Role,
		AuthProvider: user.AuthProvider,
		AuthSub:      user.AuthSub,
		Scope:        scope,
		SessionID:    sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   "user:" + strconv.FormatInt(user.ID, 10),
			Audience:  jwt.ClaimStrings(audiences),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return identityJWTResult{}, err
	}
	return identityJWTResult{
		Token:     signed,
		Issuer:    s.issuer,
		Audiences: append([]string(nil), audiences...),
		Scope:     scope,
		ExpiresAt: expiresAt,
	}, nil
}
