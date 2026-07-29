package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrDisabledUser       = errors.New("disabled user")
	ErrAdminPasswordEmpty = errors.New("admin password is required")
)

type User struct {
	ID           int64      `json:"id"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"displayName"`
	AvatarURL    string     `json:"avatarUrl"`
	AuthProvider string     `json:"authProvider"`
	AuthSub      string     `json:"-"`
	Role         string     `json:"role"`
	Enabled      bool       `json:"enabled"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
	PasswordHash string     `json:"-"`
}

type AuthentikIdentity struct {
	Subject  string
	Email    string
	Name     string
	Username string
	Picture  string
}

type LoginLog struct {
	UserID        *int64
	Email         string
	DisplayName   string
	AuthMethod    string
	LoginResult   string
	FailureReason string
	IP            string
	UserAgent     string
	LoginAt       time.Time
}

type EmailCodeChallenge struct {
	ID        int64
	Email     string
	CodeHash  string
	ExpiresAt time.Time
}

type OAuthRequest struct {
	Kind         string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	CallbackURL  string
	DesktopState string
	ExpiresAt    time.Time
}

type DownloadStat struct {
	InstallerKey string `json:"installerKey"`
	Total        int64  `json:"total"`
}

type DownloadEvent struct {
	ID             int64     `json:"id"`
	InstallerKey   string    `json:"installerKey"`
	Version        string    `json:"version"`
	ClientIP       string    `json:"clientIp"`
	RemoteAddr     string    `json:"remoteAddr"`
	XForwardedFor  string    `json:"xForwardedFor"`
	XRealIP        string    `json:"xRealIp"`
	UserAgent      string    `json:"userAgent"`
	Referer        string    `json:"referer"`
	AcceptLanguage string    `json:"acceptLanguage"`
	DownloadedAt   time.Time `json:"downloadedAt"`
}

type Store interface {
	EnsureSchema(ctx context.Context) error
	EnsureAdmin(ctx context.Context, email, passwordHash string) error
	FindLocalUserByEmail(ctx context.Context, email string) (User, error)
	FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error)
	UpsertGoogleUser(ctx context.Context, identity GoogleIdentity, ip string) (User, error)
	UpsertAuthentikUser(ctx context.Context, identity AuthentikIdentity, ip string) (User, error)
	UpsertEmailCodeUser(ctx context.Context, email, ip string) (User, error)
	SaveEmailCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error
	ConsumeEmailCode(ctx context.Context, email, codeHash string, now time.Time) error
	SaveOAuthRequest(ctx context.Context, stateHash string, request OAuthRequest) error
	ConsumeOAuthRequest(ctx context.Context, stateHash string, now time.Time) (OAuthRequest, error)
	CreateSession(ctx context.Context, userID int64, tokenHash, csrfToken string, expiresAt time.Time, userAgent, ip string) error
	FindSessionCSRF(ctx context.Context, tokenHash string, now time.Time) (string, error)
	RevokeSession(ctx context.Context, tokenHash string) error
	SaveDesktopSsoTicket(ctx context.Context, userID int64, ticketHash string, expiresAt time.Time, ip, userAgent string) error
	ConsumeDesktopSsoTicket(ctx context.Context, ticketHash string, now time.Time) (User, error)
	TouchLastLogin(ctx context.Context, userID int64, loggedInAt time.Time) error
	RecordLogin(ctx context.Context, entry LoginLog) error
}

type MySQLStore struct {
	db *sql.DB
}

func OpenMySQL(ctx context.Context, dsn string) (*MySQLStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &MySQLStore{db: db}, nil
}

func (s *MySQLStore) Close() error {
	return s.db.Close()
}

func (s *MySQLStore) EnsureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS auth_user (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			EMAIL_ VARCHAR(255) NOT NULL DEFAULT '',
			DISPLAY_NAME_ VARCHAR(255) NOT NULL DEFAULT '',
			AVATAR_URL_ VARCHAR(1024) NOT NULL DEFAULT '',
			AUTH_PROVIDER_ VARCHAR(32) NOT NULL DEFAULT 'local',
			AUTH_SUB_ VARCHAR(255) NOT NULL DEFAULT '',
			ROLE_ VARCHAR(32) NOT NULL DEFAULT 'user',
			ENABLED_ TINYINT(1) NOT NULL DEFAULT 1,
			CREATED_AT_ DATETIME(3) NOT NULL,
			UPDATED_AT_ DATETIME(3) NOT NULL,
			LAST_LOGIN_AT_ DATETIME(3) NULL,
			PRIMARY KEY (ID_),
			UNIQUE KEY UK_AUTH_USER_PROVIDER_SUB (AUTH_PROVIDER_, AUTH_SUB_),
			KEY IDX_AUTH_USER_EMAIL (EMAIL_)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_local_credential (
			USER_ID_ BIGINT UNSIGNED NOT NULL,
			PASSWORD_HASH_ VARCHAR(255) NOT NULL,
			PASSWORD_UPDATED_AT_ DATETIME(3) NOT NULL,
			CREATED_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (USER_ID_),
			CONSTRAINT FK_AUTH_LOCAL_CREDENTIAL_USER FOREIGN KEY (USER_ID_) REFERENCES auth_user (ID_) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_identity (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			USER_ID_ BIGINT UNSIGNED NOT NULL,
			PROVIDER_ VARCHAR(32) NOT NULL,
			SUBJECT_ VARCHAR(255) NOT NULL,
			EMAIL_ VARCHAR(255) NOT NULL DEFAULT '',
			EMAIL_VERIFIED_ TINYINT(1) NOT NULL DEFAULT 0,
			CREATED_AT_ DATETIME(3) NOT NULL,
			UPDATED_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (ID_),
			UNIQUE KEY UK_AUTH_IDENTITY_PROVIDER_SUBJECT (PROVIDER_, SUBJECT_),
			KEY IDX_AUTH_IDENTITY_USER (USER_ID_),
			KEY IDX_AUTH_IDENTITY_EMAIL (EMAIL_),
			CONSTRAINT FK_AUTH_IDENTITY_USER FOREIGN KEY (USER_ID_) REFERENCES auth_user (ID_) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_session (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			USER_ID_ BIGINT UNSIGNED NOT NULL,
			TOKEN_HASH_ CHAR(64) NOT NULL,
			CSRF_TOKEN_ VARCHAR(64) NOT NULL DEFAULT '',
			EXPIRES_AT_ DATETIME(3) NOT NULL,
			CREATED_AT_ DATETIME(3) NOT NULL,
			LAST_SEEN_AT_ DATETIME(3) NOT NULL,
			USER_AGENT_ VARCHAR(512) NOT NULL DEFAULT '',
			IP_ VARCHAR(64) NOT NULL DEFAULT '',
			PRIMARY KEY (ID_),
			UNIQUE KEY UK_AUTH_SESSION_TOKEN_HASH (TOKEN_HASH_),
			KEY IDX_AUTH_SESSION_USER_EXPIRES (USER_ID_, EXPIRES_AT_),
			CONSTRAINT FK_AUTH_SESSION_USER FOREIGN KEY (USER_ID_) REFERENCES auth_user (ID_) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_oauth_request (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			STATE_HASH_ CHAR(64) NOT NULL,
			KIND_ VARCHAR(32) NOT NULL DEFAULT 'web',
			NONCE_ VARCHAR(128) NOT NULL,
			CODE_VERIFIER_ VARCHAR(128) NOT NULL,
			RETURN_TO_ VARCHAR(2048) NOT NULL DEFAULT '/',
			CALLBACK_URL_ VARCHAR(2048) NOT NULL DEFAULT '',
			DESKTOP_STATE_ VARCHAR(512) NOT NULL DEFAULT '',
			EXPIRES_AT_ DATETIME(3) NOT NULL,
			CONSUMED_AT_ DATETIME(3) NULL,
			CREATED_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (ID_),
			UNIQUE KEY UK_AUTH_OAUTH_REQUEST_STATE_HASH (STATE_HASH_),
			KEY IDX_AUTH_OAUTH_REQUEST_EXPIRES (EXPIRES_AT_)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_desktop_sso_ticket (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			USER_ID_ BIGINT UNSIGNED NOT NULL,
			TICKET_HASH_ CHAR(64) NOT NULL,
			EXPIRES_AT_ DATETIME(3) NOT NULL,
			CONSUMED_AT_ DATETIME(3) NULL,
			CREATED_AT_ DATETIME(3) NOT NULL,
			IP_ VARCHAR(64) NOT NULL DEFAULT '',
			USER_AGENT_ VARCHAR(512) NOT NULL DEFAULT '',
			PRIMARY KEY (ID_),
			UNIQUE KEY UK_AUTH_DESKTOP_SSO_TICKET_HASH (TICKET_HASH_),
			KEY IDX_AUTH_DESKTOP_SSO_TICKET_EXPIRES (EXPIRES_AT_),
			KEY IDX_AUTH_DESKTOP_SSO_TICKET_USER (USER_ID_),
			CONSTRAINT FK_AUTH_DESKTOP_SSO_TICKET_USER FOREIGN KEY (USER_ID_) REFERENCES auth_user (ID_) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_login_log (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			USER_ID_ BIGINT UNSIGNED NULL,
			EMAIL_ VARCHAR(255) NOT NULL DEFAULT '',
			DISPLAY_NAME_ VARCHAR(255) NOT NULL DEFAULT '',
			AUTH_METHOD_ VARCHAR(32) NOT NULL,
			LOGIN_RESULT_ VARCHAR(16) NOT NULL,
			FAILURE_REASON_ VARCHAR(128) NOT NULL DEFAULT '',
			IP_ VARCHAR(64) NOT NULL DEFAULT '',
			USER_AGENT_ VARCHAR(512) NOT NULL DEFAULT '',
			LOGIN_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (ID_),
			KEY IDX_AUTH_LOGIN_LOG_USER_AT (USER_ID_, LOGIN_AT_),
			KEY IDX_AUTH_LOGIN_LOG_METHOD_AT (AUTH_METHOD_, LOGIN_AT_),
			CONSTRAINT FK_AUTH_LOGIN_LOG_USER FOREIGN KEY (USER_ID_) REFERENCES auth_user (ID_) ON DELETE SET NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS auth_email_code (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			EMAIL_ VARCHAR(255) NOT NULL,
			CODE_HASH_ CHAR(64) NOT NULL,
			EXPIRES_AT_ DATETIME(3) NOT NULL,
			CONSUMED_AT_ DATETIME(3) NULL,
			CREATED_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (ID_),
			KEY IDX_AUTH_EMAIL_CODE_EMAIL_CREATED (EMAIL_, CREATED_AT_),
			KEY IDX_AUTH_EMAIL_CODE_EXPIRES (EXPIRES_AT_)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE auth_session ADD COLUMN CSRF_TOKEN_ VARCHAR(64) NOT NULL DEFAULT '' AFTER TOKEN_HASH_`); err != nil {
		var mysqlErr *mysqlDriver.MySQLError
		if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1060 {
			return err
		}
	}
	return nil
}

func (s *MySQLStore) EnsureAdmin(ctx context.Context, email, passwordHash string) error {
	email = normalizeEmail(email)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO auth_user (EMAIL_, DISPLAY_NAME_, AUTH_PROVIDER_, AUTH_SUB_, ROLE_, ENABLED_, CREATED_AT_, UPDATED_AT_)
		 VALUES (?, ?, 'local', ?, 'admin', 1, ?, ?)
		 ON DUPLICATE KEY UPDATE ROLE_ = IF(ROLE_ = 'admin', ROLE_, 'admin'), UPDATED_AT_ = VALUES(UPDATED_AT_)`,
		email,
		email,
		email,
		now,
		now,
	)
	if err != nil {
		return err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if userID == 0 {
		row := tx.QueryRowContext(ctx, `SELECT ID_ FROM auth_user WHERE AUTH_PROVIDER_ = 'local' AND AUTH_SUB_ = ?`, email)
		if err := row.Scan(&userID); err != nil {
			return err
		}
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO auth_local_credential (USER_ID_, PASSWORD_HASH_, PASSWORD_UPDATED_AT_, CREATED_AT_)
		 VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE PASSWORD_HASH_ = PASSWORD_HASH_`,
		userID,
		passwordHash,
		now,
		now,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *MySQLStore) FindLocalUserByEmail(ctx context.Context, email string) (User, error) {
	row := s.db.QueryRowContext(
		ctx,
		userSelectList+`
		 , c.PASSWORD_HASH_
		 FROM auth_user u
		 INNER JOIN auth_local_credential c ON c.USER_ID_ = u.ID_
		 WHERE u.AUTH_PROVIDER_ = 'local' AND u.EMAIL_ = ?`,
		normalizeEmail(email),
	)
	return scanUserWithPassword(row)
}

func (s *MySQLStore) FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error) {
	row := s.db.QueryRowContext(
		ctx,
		userSelectList+`
		 , '' AS PASSWORD_HASH_
		 FROM auth_session sess
		 INNER JOIN auth_user u ON u.ID_ = sess.USER_ID_
		 WHERE sess.TOKEN_HASH_ = ? AND sess.EXPIRES_AT_ > ?`,
		tokenHash,
		now,
	)
	user, err := scanUserWithPassword(row)
	if err != nil {
		return user, err
	}
	if !user.Enabled {
		return user, ErrDisabledUser
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE auth_session SET LAST_SEEN_AT_ = ? WHERE TOKEN_HASH_ = ?`, now, tokenHash)
	return user, nil
}

func (s *MySQLStore) UpsertGoogleUser(ctx context.Context, identity GoogleIdentity, ip string) (User, error) {
	_ = ip
	if !identity.EmailVerified {
		return User{}, ErrNotFound
	}
	return s.upsertIdentityUser(
		ctx,
		"google",
		strings.TrimSpace(identity.Subject),
		normalizeEmail(identity.Email),
		strings.TrimSpace(identity.Name),
		strings.TrimSpace(identity.Picture),
	)
}

func (s *MySQLStore) UpsertAuthentikUser(ctx context.Context, identity AuthentikIdentity, ip string) (User, error) {
	now := time.Now().UTC()
	subject := strings.TrimSpace(identity.Subject)
	email := normalizeEmail(identity.Email)
	if subject == "" || !validEmail(email) {
		return User{}, ErrNotFound
	}
	displayName := strings.TrimSpace(identity.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(identity.Username)
	}
	if displayName == "" {
		displayName = email
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_user (EMAIL_, DISPLAY_NAME_, AVATAR_URL_, AUTH_PROVIDER_, AUTH_SUB_, ROLE_, ENABLED_, CREATED_AT_, UPDATED_AT_, LAST_LOGIN_AT_)
		 VALUES (?, ?, ?, 'authentik', ?, 'user', 1, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   EMAIL_ = VALUES(EMAIL_),
		   DISPLAY_NAME_ = VALUES(DISPLAY_NAME_),
		   AVATAR_URL_ = VALUES(AVATAR_URL_),
		   UPDATED_AT_ = VALUES(UPDATED_AT_),
		   LAST_LOGIN_AT_ = VALUES(LAST_LOGIN_AT_)`,
		email,
		displayName,
		strings.TrimSpace(identity.Picture),
		subject,
		now,
		now,
		now,
	)
	if err != nil {
		return User{}, err
	}

	row := s.db.QueryRowContext(
		ctx,
		userSelectList+`
		 , '' AS PASSWORD_HASH_
		 FROM auth_user u
		 WHERE u.AUTH_PROVIDER_ = 'authentik' AND u.AUTH_SUB_ = ?`,
		subject,
	)
	user, err := scanUserWithPassword(row)
	if err != nil {
		return User{}, err
	}
	_ = ip
	return user, nil
}

func (s *MySQLStore) UpsertEmailCodeUser(ctx context.Context, email, ip string) (User, error) {
	_ = ip
	email = normalizeEmail(email)
	return s.upsertIdentityUser(ctx, "email_code", email, email, email, "")
}

func (s *MySQLStore) upsertIdentityUser(
	ctx context.Context,
	provider, subject, email, displayName, avatarURL string,
) (User, error) {
	provider = strings.TrimSpace(provider)
	subject = strings.TrimSpace(subject)
	email = normalizeEmail(email)
	if provider == "" || subject == "" || !validEmail(email) {
		return User{}, ErrNotFound
	}
	if displayName = strings.TrimSpace(displayName); displayName == "" {
		displayName = email
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var userID int64
	row := tx.QueryRowContext(
		ctx,
		`SELECT USER_ID_ FROM auth_identity WHERE PROVIDER_ = ? AND SUBJECT_ = ? FOR UPDATE`,
		provider,
		subject,
	)
	err = row.Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		row = tx.QueryRowContext(
			ctx,
			`SELECT ID_ FROM auth_user WHERE EMAIL_ = ? ORDER BY (ROLE_ = 'admin') DESC, ID_ ASC LIMIT 1 FOR UPDATE`,
			email,
		)
		err = row.Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			result, insertErr := tx.ExecContext(
				ctx,
				`INSERT INTO auth_user
				 (EMAIL_, DISPLAY_NAME_, AVATAR_URL_, AUTH_PROVIDER_, AUTH_SUB_, ROLE_, ENABLED_, CREATED_AT_, UPDATED_AT_, LAST_LOGIN_AT_)
				 VALUES (?, ?, ?, ?, ?, 'user', 1, ?, ?, ?)`,
				email,
				displayName,
				avatarURL,
				provider,
				subject,
				now,
				now,
				now,
			)
			if insertErr != nil {
				return User{}, insertErr
			}
			userID, err = result.LastInsertId()
		}
		if err != nil {
			return User{}, err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO auth_identity
			 (USER_ID_, PROVIDER_, SUBJECT_, EMAIL_, EMAIL_VERIFIED_, CREATED_AT_, UPDATED_AT_)
			 VALUES (?, ?, ?, ?, 1, ?, ?)`,
			userID,
			provider,
			subject,
			email,
			now,
			now,
		); err != nil {
			return User{}, err
		}
	} else if err != nil {
		return User{}, err
	}

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE auth_user
		 SET EMAIL_ = ?, DISPLAY_NAME_ = IF(? = '', DISPLAY_NAME_, ?),
		     AVATAR_URL_ = IF(? = '', AVATAR_URL_, ?), UPDATED_AT_ = ?, LAST_LOGIN_AT_ = ?
		 WHERE ID_ = ?`,
		email,
		displayName,
		displayName,
		avatarURL,
		avatarURL,
		now,
		now,
		userID,
	); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE auth_identity SET EMAIL_ = ?, EMAIL_VERIFIED_ = 1, UPDATED_AT_ = ?
		 WHERE PROVIDER_ = ? AND SUBJECT_ = ?`,
		email,
		now,
		provider,
		subject,
	); err != nil {
		return User{}, err
	}

	user, err := scanUserWithPassword(tx.QueryRowContext(
		ctx,
		userSelectList+`, '' AS PASSWORD_HASH_ FROM auth_user u WHERE u.ID_ = ?`,
		userID,
	))
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *MySQLStore) SaveEmailCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error {
	now := time.Now().UTC()
	email = normalizeEmail(email)
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_email_code (EMAIL_, CODE_HASH_, EXPIRES_AT_, CREATED_AT_)
		 VALUES (?, ?, ?, ?)`,
		email,
		codeHash,
		expiresAt,
		now,
	)
	return err
}

func (s *MySQLStore) ConsumeEmailCode(ctx context.Context, email, codeHash string, now time.Time) error {
	email = normalizeEmail(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var challenge EmailCodeChallenge
	row := tx.QueryRowContext(
		ctx,
		`SELECT ID_, EMAIL_, CODE_HASH_, EXPIRES_AT_
		 FROM auth_email_code
		 WHERE EMAIL_ = ? AND CONSUMED_AT_ IS NULL
		 ORDER BY CREATED_AT_ DESC
		 LIMIT 1
		 FOR UPDATE`,
		email,
	)
	if err := row.Scan(&challenge.ID, &challenge.Email, &challenge.CodeHash, &challenge.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !challenge.ExpiresAt.After(now) || challenge.CodeHash != codeHash {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_email_code SET CONSUMED_AT_ = ? WHERE ID_ = ?`, now, challenge.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *MySQLStore) SaveOAuthRequest(ctx context.Context, stateHash string, request OAuthRequest) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_oauth_request
		 (STATE_HASH_, KIND_, NONCE_, CODE_VERIFIER_, RETURN_TO_, CALLBACK_URL_, DESKTOP_STATE_, EXPIRES_AT_, CREATED_AT_)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stateHash,
		truncate(strings.TrimSpace(request.Kind), 32),
		truncate(strings.TrimSpace(request.Nonce), 128),
		truncate(strings.TrimSpace(request.CodeVerifier), 128),
		truncate(strings.TrimSpace(request.ReturnTo), 2048),
		truncate(strings.TrimSpace(request.CallbackURL), 2048),
		truncate(strings.TrimSpace(request.DesktopState), 512),
		request.ExpiresAt,
		now,
	)
	return err
}

func (s *MySQLStore) ConsumeOAuthRequest(ctx context.Context, stateHash string, now time.Time) (OAuthRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthRequest{}, err
	}
	defer tx.Rollback()

	var request OAuthRequest
	row := tx.QueryRowContext(
		ctx,
		`SELECT KIND_, NONCE_, CODE_VERIFIER_, RETURN_TO_, CALLBACK_URL_, DESKTOP_STATE_, EXPIRES_AT_
		 FROM auth_oauth_request
		 WHERE STATE_HASH_ = ? AND CONSUMED_AT_ IS NULL
		 FOR UPDATE`,
		stateHash,
	)
	if err := row.Scan(
		&request.Kind,
		&request.Nonce,
		&request.CodeVerifier,
		&request.ReturnTo,
		&request.CallbackURL,
		&request.DesktopState,
		&request.ExpiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OAuthRequest{}, ErrNotFound
		}
		return OAuthRequest{}, err
	}
	if !request.ExpiresAt.After(now) {
		return OAuthRequest{}, ErrNotFound
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE auth_oauth_request SET CONSUMED_AT_ = ? WHERE STATE_HASH_ = ?`,
		now,
		stateHash,
	); err != nil {
		return OAuthRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthRequest{}, err
	}
	return request, nil
}

func (s *MySQLStore) CreateSession(ctx context.Context, userID int64, tokenHash, csrfToken string, expiresAt time.Time, userAgent, ip string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_session (USER_ID_, TOKEN_HASH_, CSRF_TOKEN_, EXPIRES_AT_, CREATED_AT_, LAST_SEEN_AT_, USER_AGENT_, IP_)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		tokenHash,
		csrfToken,
		expiresAt,
		now,
		now,
		truncate(strings.TrimSpace(userAgent), 512),
		truncate(strings.TrimSpace(ip), 64),
	)
	return err
}

func (s *MySQLStore) FindSessionCSRF(ctx context.Context, tokenHash string, now time.Time) (string, error) {
	var csrfToken string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT CSRF_TOKEN_ FROM auth_session WHERE TOKEN_HASH_ = ? AND EXPIRES_AT_ > ?`,
		tokenHash,
		now,
	).Scan(&csrfToken)
	if errors.Is(err, sql.ErrNoRows) || csrfToken == "" {
		return "", ErrNotFound
	}
	return csrfToken, err
}

func (s *MySQLStore) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_session WHERE TOKEN_HASH_ = ?`, tokenHash)
	return err
}

func (s *MySQLStore) SaveDesktopSsoTicket(ctx context.Context, userID int64, ticketHash string, expiresAt time.Time, ip, userAgent string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_desktop_sso_ticket (USER_ID_, TICKET_HASH_, EXPIRES_AT_, CREATED_AT_, IP_, USER_AGENT_)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID,
		ticketHash,
		expiresAt,
		now,
		truncate(strings.TrimSpace(ip), 64),
		truncate(strings.TrimSpace(userAgent), 512),
	)
	return err
}

func (s *MySQLStore) ConsumeDesktopSsoTicket(ctx context.Context, ticketHash string, now time.Time) (User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(
		ctx,
		`UPDATE auth_desktop_sso_ticket
		 SET CONSUMED_AT_ = ?
		 WHERE TICKET_HASH_ = ? AND CONSUMED_AT_ IS NULL AND EXPIRES_AT_ > ?`,
		now,
		ticketHash,
		now,
	)
	if err != nil {
		return User{}, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if rowsAffected == 0 {
		return User{}, ErrNotFound
	}

	row := tx.QueryRowContext(
		ctx,
		userSelectList+`
		 , '' AS PASSWORD_HASH_
		 FROM auth_desktop_sso_ticket ticket
		 INNER JOIN auth_user u ON u.ID_ = ticket.USER_ID_
		 WHERE ticket.TICKET_HASH_ = ?`,
		ticketHash,
	)
	user, err := scanUserWithPassword(row)
	if err != nil {
		return user, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	if !user.Enabled {
		return user, ErrDisabledUser
	}
	return user, nil
}

func (s *MySQLStore) TouchLastLogin(ctx context.Context, userID int64, loggedInAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_user SET LAST_LOGIN_AT_ = ?, UPDATED_AT_ = ? WHERE ID_ = ?`, loggedInAt, loggedInAt, userID)
	return err
}

func (s *MySQLStore) RecordLogin(ctx context.Context, entry LoginLog) error {
	if entry.LoginAt.IsZero() {
		entry.LoginAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_login_log (USER_ID_, EMAIL_, DISPLAY_NAME_, AUTH_METHOD_, LOGIN_RESULT_, FAILURE_REASON_, IP_, USER_AGENT_, LOGIN_AT_)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.UserID,
		truncate(normalizeEmail(entry.Email), 255),
		truncate(strings.TrimSpace(entry.DisplayName), 255),
		truncate(strings.TrimSpace(entry.AuthMethod), 32),
		truncate(strings.TrimSpace(entry.LoginResult), 16),
		truncate(strings.TrimSpace(entry.FailureReason), 128),
		truncate(strings.TrimSpace(entry.IP), 64),
		truncate(strings.TrimSpace(entry.UserAgent), 512),
		entry.LoginAt,
	)
	return err
}

const userSelectList = `SELECT u.ID_, u.EMAIL_, u.DISPLAY_NAME_, u.AVATAR_URL_, u.AUTH_PROVIDER_, u.AUTH_SUB_, u.ROLE_, u.ENABLED_, u.LAST_LOGIN_AT_`

type scanner interface {
	Scan(dest ...any) error
}

func scanUserWithPassword(row scanner) (User, error) {
	var user User
	var lastLogin sql.NullTime
	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.DisplayName,
		&user.AvatarURL,
		&user.AuthProvider,
		&user.AuthSub,
		&user.Role,
		&user.Enabled,
		&lastLogin,
		&user.PasswordHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrNotFound
		}
		return user, err
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}
	return user, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
