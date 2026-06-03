package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
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

type DownloadStat struct {
	InstallerKey string `json:"installerKey"`
	Total        int64  `json:"total"`
}

type Store interface {
	EnsureSchema(ctx context.Context) error
	EnsureAdmin(ctx context.Context, email, passwordHash string) error
	FindLocalUserByEmail(ctx context.Context, email string) (User, error)
	FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error)
	UpsertGoogleUser(ctx context.Context, identity GoogleIdentity, ip string) (User, error)
	UpsertEmailCodeUser(ctx context.Context, email, ip string) (User, error)
	SaveEmailCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error
	ConsumeEmailCode(ctx context.Context, email, codeHash string, now time.Time) error
	CreateSession(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time, userAgent, ip string) error
	RevokeSession(ctx context.Context, tokenHash string) error
	TouchLastLogin(ctx context.Context, userID int64, loggedInAt time.Time) error
	RecordLogin(ctx context.Context, entry LoginLog) error
	ListDownloadStats(ctx context.Context) ([]DownloadStat, error)
	IncrementDownloadCount(ctx context.Context, installerKey string) error
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
		`CREATE TABLE IF NOT EXISTS auth_session (
			ID_ BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			USER_ID_ BIGINT UNSIGNED NOT NULL,
			TOKEN_HASH_ CHAR(64) NOT NULL,
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
		`CREATE TABLE IF NOT EXISTS download_stat (
			INSTALLER_KEY_ VARCHAR(64) NOT NULL,
			TOTAL_ BIGINT UNSIGNED NOT NULL DEFAULT 0,
			CREATED_AT_ DATETIME(3) NOT NULL,
			UPDATED_AT_ DATETIME(3) NOT NULL,
			PRIMARY KEY (INSTALLER_KEY_)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
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
	now := time.Now().UTC()
	email := normalizeEmail(identity.Email)
	displayName := strings.TrimSpace(identity.Name)
	if displayName == "" {
		displayName = email
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_user (EMAIL_, DISPLAY_NAME_, AVATAR_URL_, AUTH_PROVIDER_, AUTH_SUB_, ROLE_, ENABLED_, CREATED_AT_, UPDATED_AT_, LAST_LOGIN_AT_)
		 VALUES (?, ?, ?, 'google', ?, 'user', 1, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   EMAIL_ = VALUES(EMAIL_),
		   DISPLAY_NAME_ = VALUES(DISPLAY_NAME_),
		   AVATAR_URL_ = VALUES(AVATAR_URL_),
		   UPDATED_AT_ = VALUES(UPDATED_AT_),
		   LAST_LOGIN_AT_ = VALUES(LAST_LOGIN_AT_)`,
		email,
		displayName,
		strings.TrimSpace(identity.Picture),
		strings.TrimSpace(identity.Subject),
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
		 WHERE u.AUTH_PROVIDER_ = 'google' AND u.AUTH_SUB_ = ?`,
		strings.TrimSpace(identity.Subject),
	)
	user, err := scanUserWithPassword(row)
	if err != nil {
		return User{}, err
	}
	_ = ip
	return user, nil
}

func (s *MySQLStore) UpsertEmailCodeUser(ctx context.Context, email, ip string) (User, error) {
	now := time.Now().UTC()
	email = normalizeEmail(email)
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_user (EMAIL_, DISPLAY_NAME_, AUTH_PROVIDER_, AUTH_SUB_, ROLE_, ENABLED_, CREATED_AT_, UPDATED_AT_, LAST_LOGIN_AT_)
		 VALUES (?, ?, 'email_code', ?, 'user', 1, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   EMAIL_ = VALUES(EMAIL_),
		   DISPLAY_NAME_ = IF(DISPLAY_NAME_ = '' OR DISPLAY_NAME_ = AUTH_SUB_, VALUES(DISPLAY_NAME_), DISPLAY_NAME_),
		   UPDATED_AT_ = VALUES(UPDATED_AT_),
		   LAST_LOGIN_AT_ = VALUES(LAST_LOGIN_AT_)`,
		email,
		email,
		email,
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
		 WHERE u.AUTH_PROVIDER_ = 'email_code' AND u.AUTH_SUB_ = ?`,
		email,
	)
	user, err := scanUserWithPassword(row)
	if err != nil {
		return User{}, err
	}
	_ = ip
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

func (s *MySQLStore) CreateSession(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time, userAgent, ip string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_session (USER_ID_, TOKEN_HASH_, EXPIRES_AT_, CREATED_AT_, LAST_SEEN_AT_, USER_AGENT_, IP_)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID,
		tokenHash,
		expiresAt,
		now,
		now,
		truncate(strings.TrimSpace(userAgent), 512),
		truncate(strings.TrimSpace(ip), 64),
	)
	return err
}

func (s *MySQLStore) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_session WHERE TOKEN_HASH_ = ?`, tokenHash)
	return err
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

func (s *MySQLStore) ListDownloadStats(ctx context.Context) ([]DownloadStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT INSTALLER_KEY_, TOTAL_ FROM download_stat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []DownloadStat
	for rows.Next() {
		var stat DownloadStat
		if err := rows.Scan(&stat.InstallerKey, &stat.Total); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stats, nil
}

func (s *MySQLStore) IncrementDownloadCount(ctx context.Context, installerKey string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO download_stat (INSTALLER_KEY_, TOTAL_, CREATED_AT_, UPDATED_AT_)
		 VALUES (?, 1, ?, ?)
		 ON DUPLICATE KEY UPDATE TOTAL_ = TOTAL_ + 1, UPDATED_AT_ = VALUES(UPDATED_AT_)`,
		truncate(strings.TrimSpace(installerKey), 64),
		now,
		now,
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
