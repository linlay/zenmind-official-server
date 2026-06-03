package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Mailer interface {
	SendEmailCode(ctx context.Context, to, code string) error
}

type SMTPMailerConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type SMTPMailer struct {
	host     string
	port     string
	username string
	password string
	from     string
}

func NewSMTPMailer(cfg SMTPMailerConfig) Mailer {
	host := strings.TrimSpace(cfg.Host)
	port := strings.TrimSpace(cfg.Port)
	if port == "" {
		port = "587"
	}
	from := strings.TrimSpace(cfg.From)
	if from == "" {
		from = strings.TrimSpace(cfg.Username)
	}
	if host == "" || from == "" || strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
		return disabledMailer{}
	}
	return SMTPMailer{
		host:     host,
		port:     port,
		username: strings.TrimSpace(cfg.Username),
		password: cfg.Password,
		from:     from,
	}
}

func (m SMTPMailer) SendEmailCode(ctx context.Context, to, code string) error {
	to = normalizeEmail(to)
	if to == "" {
		return fmt.Errorf("recipient email is empty")
	}

	addr := net.JoinHostPort(m.host, m.port)
	subject := "Your ZenMind verification code"
	body := fmt.Sprintf("Your ZenMind verification code is %s. It expires in 10 minutes.\n\nIf you did not request this code, you can ignore this email.\n", code)
	message := strings.Join([]string{
		"From: ZenMind <" + m.from + ">",
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := client.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
		return err
	}
	if err := client.Mail(m.from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

type disabledMailer struct{}

func (disabledMailer) SendEmailCode(context.Context, string, string) error {
	return fmt.Errorf("email delivery is not configured")
}
