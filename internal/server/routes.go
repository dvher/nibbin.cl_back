package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"text/template"
	"time"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/pkg/argon2"
	"github.com/dvher/nibbin.cl_back/pkg/models"
	"github.com/gin-gonic/gin"
	gomail "gopkg.in/mail.v2"
)

type OTPData struct {
	tries  int
	code   *big.Int
	action string
}

var mailToOTP = make(map[string]OTPData)

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func login(c *gin.Context) {

	var data models.LoginRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	to := data.Email

	if to == "" {
		log.Println("Email not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not provided",
		})
		return
	}

	if !validateEmail(to) {
		log.Println("Invalid email")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid email",
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
		tries:  0,
		code:   num,
		action: "login",
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

func register(c *gin.Context) {
	puntos := 0

	var data models.RegisterRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	if data.Nombre == "" || data.Apellido == "" || data.Email == "" || data.User == "" || data.Direccion == "" ||
		data.Telefono == "" {
		log.Println("Missing data")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Missing data",
		})
		return
	}

	if !validateEmail(data.Email) {
		log.Println("Invalid email")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid email",
		})
		return
	}

	stmt, err := db.DB.Prepare(
		"INSERT INTO Usuario(nombre, apellido, email, usuario, puntos, direccion, telefono) VALUES(?, ?, ?, ?, ?, ?, ?);",
	)

	if err != nil {
		log.Println("Error preparing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(data.Nombre, data.Apellido, data.Email, data.User, puntos, data.Direccion, data.Telefono)

	if err != nil {
		log.Println("Error inserting user")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error inserting user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created",
	})
}

func loginAdmin(c *gin.Context) {
	var data models.LoginAdminRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	if data.User == "" || data.Password == "" {
		log.Println("Missing data")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Missing data",
		})
		return
	}

	stmt, err := db.DB.Prepare(
		"SELECT Administrador.id, idUsuario, contrasena FROM Administrador, Usuario WHERE Usuario.usuario = ?;",
	)

	if err != nil {
		log.Println("Error preparing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var id int
	var idUsuario int
	var hashedPassword string

	err = stmt.QueryRow(data.User).Scan(&id, &idUsuario, &hashedPassword)

	if err != nil {
		log.Println("Error querying user")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	err = stmt.Close()

	if err != nil {
		log.Println("Error closing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error closing statement",
		})
		return
	}

	stmt, err = db.DB.Prepare("SELECT email FROM Usuario WHERE id = ?;")

	if err != nil {
		log.Println("Error preparing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var email string

	err = stmt.QueryRow(idUsuario).Scan(&email)

	if err != nil {
		log.Println("Error querying user")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	isValid, err := argon2.ComparePasswordHash(data.Password, hashedPassword)

	if err != nil {
		log.Println("Error comparing password")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error comparing password",
		})
		return
	}

	if !isValid {
		log.Println("Invalid password")

		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid password",
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

	mailToOTP[email] = OTPData{
		tries:  0,
		code:   num,
		action: "loginAdmin",
	}

	body, err := parseTemplate("verification.html", struct {
		Code *big.Int
	}{
		Code: num,
	})

	if err != nil {
		log.Println("Error parsing template")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error parsing template",
		})
		return
	}

	err = sendEmail([]string{email}, "Verification code", body)

	if err != nil {
		log.Println("Error sending mail")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error sending mail",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
	})
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

	str := fmt.Sprintf("%s verified", mailToOTP[email].action)

	delete(mailToOTP, email)

	c.JSON(http.StatusOK, gin.H{
		"message": str,
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

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)

	return err == nil
}
