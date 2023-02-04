package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"log"
	"math/big"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gomail "gopkg.in/mail.v2"
)

func sendEmail(to []string, subject, body string) error {
	message := gomail.NewMessage()
	from := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort, err := strconv.Atoi(os.Getenv("SMTP_PORT"))

	if err != nil {
		log.Println("Error converting port to int", err)
		return err
	}

	message.SetHeader("From", from)
	message.SetHeader("To", to...)

	message.SetHeader("Subject", subject)

	message.SetBody("text/html", body)

	d := gomail.NewDialer(smtpHost, smtpPort, from, password)

	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(message); err != nil {
		log.Println("Error sending email")
		return err
	}

	return nil
}

func sendOTPEmail(to []string, action string) error {

	code, err := rand.Int(rand.Reader, big.NewInt(899999))

	if err != nil {
		return err
	}

	code.Add(code, big.NewInt(100000))

	mailToOTP[to[0]] = OTPData{
		Tries:  0,
		Code:   code,
		Action: action,
	}

	if strings.HasPrefix(action, "registerAdmin") {

		t, err := parseTemplate("register.html", struct {
			Code  *big.Int
			Email string
		}{
			Code:  code,
			Email: to[0],
		})

		if err != nil {
			return err
		}

		admin_email := os.Getenv("ADMIN_EMAIL")

		err = sendEmail([]string{admin_email}, "Registrar administrador", t)

		if err != nil {
			return err
		}

		return nil

	}

	t, err := parseTemplate("verification.html", struct {
		Code *big.Int
	}{
		Code: code,
	})

	if err != nil {
		return err
	}

	err = sendEmail(to, "Código de verificación", t)

	if err != nil {
		return err
	}

	timer := time.NewTimer(3 * time.Minute)

	go func() {
		select {
		case <-timer.C:
			delete(mailToOTP, to[0])
			break
		case <-mailToChan[to[0]]:
			break
		}
	}()

	return nil
}

func parseTemplate(templateName string, data any) (string, error) {
	var body bytes.Buffer

	t, err := template.ParseFiles("templates/" + templateName)

	if err != nil {
		log.Println("Error parsing email template", err)
		return "", err
	}

	err = t.Execute(&body, data)

	if err != nil {
		log.Println("Error executing email template", err)
		return "", err
	}

	return body.String(), nil
}

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)

	return err == nil
}

func isLogged(c *gin.Context) {
	sess := sessions.Default(c)

	if sess.Get("user") == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
		return
	}

	log.Println(sess.Get("user"))

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged",
		"user":    sess.Get("user"),
	})
}
