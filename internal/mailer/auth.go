package mailer

import (
	"net/smtp"
	"strings"
)

type loginAuth struct {
	username, password string
}

// LoginAuth returns an smtp.Auth that implements the LOGIN authentication mechanism.
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password}
}

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		challenge := strings.ToLower(string(fromServer))
		if strings.Contains(challenge, "user") {
			return []byte(a.username), nil
		}
		if strings.Contains(challenge, "pass") {
			return []byte(a.password), nil
		}
		return []byte(a.password), nil
	}
	return nil, nil
}

// AuthenticateClient negotiates authentication with an upstream SMTP server,
// automatically selecting PLAIN or LOGIN based on the server's advertised AUTH extensions.
func AuthenticateClient(c *smtp.Client, host, username, password string) error {
	if username == "" {
		return nil
	}
	ok, mechs := c.Extension("AUTH")
	if ok {
		mechsUpper := strings.ToUpper(mechs)
		if strings.Contains(mechsUpper, "PLAIN") {
			if err := c.Auth(smtp.PlainAuth("", username, password, host)); err == nil {
				return nil
			}
		}
		if strings.Contains(mechsUpper, "LOGIN") {
			return c.Auth(LoginAuth(username, password))
		}
	}
	// Fallback attempt: try PLAIN first, then LOGIN
	if err := c.Auth(smtp.PlainAuth("", username, password, host)); err == nil {
		return nil
	}
	return c.Auth(LoginAuth(username, password))
}
