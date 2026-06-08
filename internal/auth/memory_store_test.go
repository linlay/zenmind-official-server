package auth

import (
	"context"
	"sync"
	"time"
)

type memoryStore struct {
	mu       sync.Mutex
	nextID   int64
	users    map[int64]User
	local    map[string]int64
	google   map[string]int64
	email    map[string]int64
	tickets  map[string]desktopSsoTicketRecord
	sessions map[string]sessionRecord
	logins   []LoginLog
	codes    []emailCodeRecord
	stats    map[string]int64
	events   []DownloadEvent
}

type sessionRecord struct {
	userID    int64
	expiresAt time.Time
	revoked   bool
}

type desktopSsoTicketRecord struct {
	userID     int64
	expiresAt  time.Time
	consumedAt *time.Time
}

type emailCodeRecord struct {
	email      string
	codeHash   string
	expiresAt  time.Time
	consumedAt *time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		nextID:   1,
		users:    map[int64]User{},
		local:    map[string]int64{},
		google:   map[string]int64{},
		email:    map[string]int64{},
		tickets:  map[string]desktopSsoTicketRecord{},
		sessions: map[string]sessionRecord{},
		stats:    map[string]int64{},
	}
}

func (s *memoryStore) EnsureSchema(context.Context) error {
	return nil
}

func (s *memoryStore) EnsureAdmin(_ context.Context, email, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email = normalizeEmail(email)
	if _, exists := s.local[email]; exists {
		return nil
	}
	user := User{
		ID:           s.nextID,
		Email:        email,
		DisplayName:  email,
		AuthProvider: "local",
		AuthSub:      email,
		PasswordHash: passwordHash,
		Role:         "admin",
		Enabled:      true,
	}
	s.nextID++
	s.users[user.ID] = user
	s.local[email] = user.ID
	return nil
}

func (s *memoryStore) FindLocalUserByEmail(_ context.Context, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID, ok := s.local[normalizeEmail(email)]
	if !ok {
		return User{}, ErrNotFound
	}
	return s.users[userID], nil
}

func (s *memoryStore) FindUserBySession(_ context.Context, tokenHash string, now time.Time) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[tokenHash]
	if !ok || session.revoked || !session.expiresAt.After(now) {
		return User{}, ErrNotFound
	}
	user, ok := s.users[session.userID]
	if !ok {
		return User{}, ErrNotFound
	}
	if !user.Enabled {
		return User{}, ErrDisabledUser
	}
	return user, nil
}

func (s *memoryStore) UpsertGoogleUser(_ context.Context, identity GoogleIdentity, _ string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	subject := normalizeEmail(identity.Subject)
	if subject == "" {
		return User{}, ErrNotFound
	}

	userID, exists := s.google[subject]
	if !exists {
		userID = s.nextID
		s.nextID++
		s.google[subject] = userID
	}

	email := normalizeEmail(identity.Email)
	displayName := identity.Name
	if displayName == "" {
		displayName = email
	}
	user := s.users[userID]
	user.ID = userID
	user.Email = email
	user.DisplayName = displayName
	user.AvatarURL = identity.Picture
	user.AuthProvider = "google"
	user.AuthSub = subject
	if !exists || user.Role == "" {
		user.Role = "user"
	}
	if !exists {
		user.Enabled = true
	}
	s.users[userID] = user
	return user, nil
}

func (s *memoryStore) UpsertEmailCodeUser(_ context.Context, email, _ string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	email = normalizeEmail(email)
	userID, exists := s.email[email]
	if !exists {
		userID = s.nextID
		s.nextID++
		s.email[email] = userID
	}

	user := s.users[userID]
	user.ID = userID
	user.Email = email
	user.DisplayName = email
	user.AuthProvider = "email_code"
	user.AuthSub = email
	user.Role = "user"
	user.Enabled = true
	s.users[userID] = user
	return user, nil
}

func (s *memoryStore) SaveEmailCode(_ context.Context, email, codeHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes = append(s.codes, emailCodeRecord{
		email:     normalizeEmail(email),
		codeHash:  codeHash,
		expiresAt: expiresAt,
	})
	return nil
}

func (s *memoryStore) ConsumeEmailCode(_ context.Context, email, codeHash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email = normalizeEmail(email)
	for i := len(s.codes) - 1; i >= 0; i-- {
		code := s.codes[i]
		if code.email != email || code.consumedAt != nil {
			continue
		}
		if !code.expiresAt.After(now) || code.codeHash != codeHash {
			return ErrNotFound
		}
		consumedAt := now
		s.codes[i].consumedAt = &consumedAt
		return nil
	}
	return ErrNotFound
}

func (s *memoryStore) CreateSession(_ context.Context, userID int64, tokenHash string, expiresAt time.Time, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[tokenHash] = sessionRecord{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *memoryStore) RevokeSession(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[tokenHash]
	if ok {
		session.revoked = true
		s.sessions[tokenHash] = session
	}
	return nil
}

func (s *memoryStore) SaveDesktopSsoTicket(_ context.Context, userID int64, ticketHash string, expiresAt time.Time, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tickets[ticketHash] = desktopSsoTicketRecord{
		userID:    userID,
		expiresAt: expiresAt,
	}
	return nil
}

func (s *memoryStore) ConsumeDesktopSsoTicket(_ context.Context, ticketHash string, now time.Time) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ticket, ok := s.tickets[ticketHash]
	if !ok || ticket.consumedAt != nil || !ticket.expiresAt.After(now) {
		return User{}, ErrNotFound
	}
	consumedAt := now
	ticket.consumedAt = &consumedAt
	s.tickets[ticketHash] = ticket

	user, ok := s.users[ticket.userID]
	if !ok {
		return User{}, ErrNotFound
	}
	if !user.Enabled {
		return user, ErrDisabledUser
	}
	return user, nil
}

func (s *memoryStore) TouchLastLogin(_ context.Context, userID int64, loggedInAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[userID]
	if !ok {
		return ErrNotFound
	}
	user.LastLoginAt = &loggedInAt
	s.users[userID] = user
	return nil
}

func (s *memoryStore) RecordLogin(_ context.Context, entry LoginLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logins = append(s.logins, entry)
	return nil
}

func (s *memoryStore) ListDownloadStats(context.Context) ([]DownloadStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := make([]DownloadStat, 0, len(s.stats))
	for key, total := range s.stats {
		stats = append(stats, DownloadStat{InstallerKey: key, Total: total})
	}
	return stats, nil
}

func (s *memoryStore) IncrementDownloadCount(_ context.Context, installerKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats[installerKey]++
	return nil
}

func (s *memoryStore) RecordDownloadEvent(_ context.Context, installerKey, version, ip, userAgent string, downloadedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, DownloadEvent{
		ID:           int64(len(s.events) + 1),
		InstallerKey: installerKey,
		Version:      version,
		IP:           ip,
		UserAgent:    userAgent,
		DownloadedAt: downloadedAt,
	})
	return nil
}
