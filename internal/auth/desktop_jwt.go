package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const desktopSsoScope = "profile market tunnel"

var errDesktopJWTNotConfigured = errors.New("desktop SSO JWT signer is not configured")

type DesktopJWTConfig struct {
	PrivateKeyFile string
	PrivateKeyPEM  string
	Issuer         string
	Audiences      []string
	KeyID          string
	TTL            time.Duration
}

type desktopJWTSigner struct {
	privateKey *rsa.PrivateKey
	issuer     string
	audiences  []string
	keyID      string
	ttl        time.Duration
	err        error
}

type desktopJWTResult struct {
	Token     string
	Issuer    string
	Audiences []string
	Scope     string
	ExpiresAt time.Time
}

func newDesktopJWTSigner(config DesktopJWTConfig) *desktopJWTSigner {
	ttl := config.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	signer := &desktopJWTSigner{
		issuer:    strings.TrimSpace(config.Issuer),
		audiences: normalizeDesktopJWTAudiences(config.Audiences),
		keyID:     strings.TrimSpace(config.KeyID),
		ttl:       ttl,
	}
	if signer.keyID == "" {
		signer.keyID = "default"
	}
	key, err := loadDesktopJWTPrivateKey(config.PrivateKeyFile, config.PrivateKeyPEM)
	if err != nil {
		signer.err = err
		return signer
	}
	signer.privateKey = key
	return signer
}

func normalizeDesktopJWTAudiences(values []string) []string {
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

func loadDesktopJWTPrivateKey(filePath, pemValue string) (*rsa.PrivateKey, error) {
	filePath = strings.TrimSpace(filePath)
	pemValue = strings.TrimSpace(pemValue)
	if filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read desktop SSO JWT private key: %w", err)
		}
		return parseDesktopJWTPrivateKeyPEM(string(content))
	}
	if pemValue == "" {
		return nil, errDesktopJWTNotConfigured
	}
	return parseDesktopJWTPrivateKeyPEM(strings.ReplaceAll(pemValue, `\n`, "\n"))
}

func parseDesktopJWTPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(value)))
	if block == nil {
		return nil, errors.New("desktop SSO JWT private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse desktop SSO JWT private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("desktop SSO JWT private key must be RSA")
	}
	return key, nil
}

func (s *desktopJWTSigner) configured() bool {
	return s != nil && s.err == nil && s.privateKey != nil && s.issuer != "" && len(s.audiences) > 0
}

func (s *desktopJWTSigner) issue(user User, now time.Time) (desktopJWTResult, error) {
	if s == nil || s.err != nil || s.privateKey == nil || s.issuer == "" || len(s.audiences) == 0 {
		if s != nil && s.err != nil && !errors.Is(s.err, errDesktopJWTNotConfigured) {
			return desktopJWTResult{}, s.err
		}
		return desktopJWTResult{}, errDesktopJWTNotConfigured
	}
	now = now.UTC()
	expiresAt := now.Add(s.ttl)
	jti, err := randomToken()
	if err != nil {
		return desktopJWTResult{}, err
	}
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": s.keyID,
	}
	claims := map[string]any{
		"iss":           s.issuer,
		"sub":           "user:" + strconv.FormatInt(user.ID, 10),
		"aud":           jwtAudienceClaim(s.audiences),
		"iat":           now.Unix(),
		"exp":           expiresAt.Unix(),
		"jti":           jti,
		"user_id":       strconv.FormatInt(user.ID, 10),
		"email":         user.Email,
		"name":          user.DisplayName,
		"picture":       user.AvatarURL,
		"role":          user.Role,
		"auth_provider": user.AuthProvider,
		"auth_sub":      user.AuthSub,
		"scope":         desktopSsoScope,
	}
	token, err := signRS256JWT(header, claims, s.privateKey)
	if err != nil {
		return desktopJWTResult{}, err
	}
	return desktopJWTResult{
		Token:     token,
		Issuer:    s.issuer,
		Audiences: append([]string(nil), s.audiences...),
		Scope:     desktopSsoScope,
		ExpiresAt: expiresAt,
	}, nil
}

func jwtAudienceClaim(audiences []string) any {
	if len(audiences) == 1 {
		return audiences[0]
	}
	return audiences
}

func signRS256JWT(header, claims map[string]any, key *rsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signedValue := headerPart + "." + payloadPart
	digest := sha256.Sum256([]byte(signedValue))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signedValue + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
