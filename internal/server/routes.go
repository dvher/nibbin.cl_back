package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	gomail "gopkg.in/mail.v2"
)

type OTPData struct {
	tries int
	code  *big.Int
}

var mailToOTP = make(map[string]OTPData)

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func login(c *gin.Context) {

	to := c.PostForm("email")

	if to == "" {
		log.Println("Email not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not provided",
		})
		return
	}

	num, err := rand.Int(rand.Reader, big.NewInt(899999))

	if err != nil {
		log.Println("Error generating OTP")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error generating OTP",
		})
		return
	}

	num.Add(num, big.NewInt(100000))

	delete(mailToOTP, to)

	mailToOTP[to] = OTPData{
		tries: 0,
		code:  num,
	}

	body, err := parseTemplate("verification.html", struct {
		Code int64
	}{
		Code: num.Int64(),
	},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error parsing template",
		})
		return
	}

	err = sendEmail([]string{to}, "Código de verificación", body)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error sending email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email sent",
	})

	timer := time.NewTimer(3 * time.Minute)

	go func() {
		<-timer.C
		delete(mailToOTP, to)
	}()
}

func verifyOTP(c *gin.Context) {
	email := c.PostForm("email")
	otp := c.PostForm("otp")
	code, err := strconv.Atoi(otp)

	if x, ok := mailToOTP[email]; ok {
		if x.tries >= 3 {
			log.Println("Too many tries")

			delete(mailToOTP, email)

			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Too many tries",
			})
			return
		}
		mailToOTP[email] = OTPData{
			tries: x.tries + 1,
			code:  x.code,
		}
	} else {
		log.Println("Email not found")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not found",
		})
		return
	}

	if err != nil {
		log.Println("Error converting otp to int")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error converting otp to int",
		})
		return
	}

	if email == "" {
		log.Println("Email not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not provided",
		})
		return
	}

	if otp == "" {
		log.Println("OTP not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "OTP not provided",
		})
		return
	}

	if big.NewInt(int64(code)).Cmp(mailToOTP[email].code) != 0 {
		log.Println("Invalid OTP")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid OTP",
		})
		return
	}

	delete(mailToOTP, email)

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP verified",
	})
}

func sendEmail(to []string, subject, body string) error {
	message := gomail.NewMessage()
	from := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort, err := strconv.Atoi(os.Getenv("SMTP_PORT"))

	if err != nil {
		log.Println("Error converting port to int")
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

func parseTemplate(templateName string, data any) (string, error) {
	var body bytes.Buffer

	t, err := template.ParseFiles("templates/" + templateName)

	if err != nil {
		log.Println("Error parsing email template")
		return "", err
	}

	err = t.Execute(&body, data)

	if err != nil {
		log.Println("Error executing email template")
		return "", err
	}

	return body.String(), nil
}
