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
	"strings"
	"text/template"
	"time"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/pkg/argon2"
	"github.com/dvher/nibbin.cl_back/pkg/models"
	"github.com/gin-gonic/gin"
	gomail "gopkg.in/mail.v2"
)

/*
TODO: Add jwt
*/

type OTPData struct {
	Tries  int
	Code   *big.Int
	Action string
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

	stmt, err := db.DB.Prepare("SELECT COUNT(id) FROM Usuario WHERE email = ?")

	if err != nil {
		log.Println("Error preparing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var count int

	err = stmt.QueryRow(to).Scan(&count)

	if err != nil {
		log.Println("Error querying database")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying database",
		})
		return
	}

	action := "login "

	if count == 0 {
		action += "unregistered"
	}

	err = sendOTPEmail([]string{to}, action)

	if err != nil {
		log.Println("Error sending email")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error sending email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email sent",
	})

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
		log.Println(err)

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

	err = sendOTPEmail([]string{email}, "loginAdmin")

	if err != nil {
		log.Println("Error sending email")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error sending email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
	})
}

func registerAdmin(c *gin.Context) {
	var data models.RegisterAdminRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	if data.Email == "" {
		log.Println("Email not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not provided",
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

	if data.Password == "" {
		log.Println("Password not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Password not provided",
		})
		return
	}

	stmt, err := db.DB.Prepare("SELECT id FROM Usuario WHERE email = ?;")

	if err != nil {
		log.Println("Error preparing statement")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var id int

	err = stmt.QueryRow(data.Email).Scan(&id)

	if err != nil {
		log.Println("Error querying user")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	hashedPassword, err := argon2.GenerateHash([]byte(data.Password), argon2.DefaultConfig())

	if err != nil {
		log.Println("Error hashing password")

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error hashing password",
		})
		return
	}

	sendOTPEmail([]string{data.Email}, "registerAdmin "+data.Email+" "+hashedPassword.String()+" "+strconv.Itoa(id))

	c.JSON(http.StatusOK, gin.H{
		"message": "Registration successful",
	})

}

func verifyOTP(c *gin.Context) {
	var data models.OTPRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	code, err := strconv.Atoi(data.OTP)

	if err != nil {
		log.Println("Error parsing OTP")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error parsing OTP",
		})
		return
	}

	if x, ok := mailToOTP[data.Email]; ok {
		if x.Tries >= 3 {
			log.Println("Too many tries")

			delete(mailToOTP, data.Email)

			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Too many tries",
			})
			return
		}
		mailToOTP[data.Email] = OTPData{
			Tries:  x.Tries + 1,
			Code:   x.Code,
			Action: x.Action,
		}
	} else {
		log.Println("Email not found")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not found",
		})
		return
	}

	if data.Email == "" {
		log.Println("Email not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email not provided",
		})
		return
	}

	if data.OTP == "" {
		log.Println("OTP not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "OTP not provided",
		})
		return
	}

	if big.NewInt(int64(code)).Cmp(mailToOTP[data.Email].Code) != 0 {
		log.Println("Invalid OTP")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid OTP",
		})
		return
	}

	if mailToOTP[data.Email].Action == "registerAdmin" {
		s := strings.Split(mailToOTP[data.Email].Action, " ")

		if len(s) != 4 {
			log.Println("Invalid action")

			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Invalid action",
			})
			return
		}

		password, id := s[2], s[3]

		stmt, err := db.DB.Prepare("INSERT INTO Administrador (idUsuario, contrasena) VALUES (?, ?);")

		if err != nil {
			log.Println("Error preparing statement")

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error preparing statement",
			})
			return
		}

		defer stmt.Close()

		_, err = stmt.Exec(id, password)

		if err != nil {
			log.Println("Error inserting admin")

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error inserting admin",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Admin registered",
		})
		return
	}

	str := fmt.Sprintf("%s verified", mailToOTP[data.Email].Action)

	delete(mailToOTP, data.Email)

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
		<-timer.C
		delete(mailToOTP, to[0])
	}()

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
