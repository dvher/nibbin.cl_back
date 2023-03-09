package server

import (
	"log"
	"net/http"
	"strconv"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/pkg/argon2"
	"github.com/dvher/nibbin.cl_back/pkg/models"
	"github.com/gin-gonic/gin"
)

func loginAdmin(c *gin.Context) {
	var data models.LoginAdminRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

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
		"SELECT Administrador.id, idUsuario, contrasena, usuario FROM Administrador, Usuario WHERE Usuario.usuario = ?;",
	)

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var id int
	var idUsuario int
	var hashedPassword string
	var usuario string

	err = stmt.QueryRow(data.User).Scan(&id, &idUsuario, &hashedPassword, &usuario)

	if err != nil {
		log.Println("Error querying user", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	err = stmt.Close()

	if err != nil {
		log.Println("Error closing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error closing statement",
		})
		return
	}

	stmt, err = db.DB.Prepare("SELECT email FROM Usuario WHERE id = ?;")

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var email string

	err = stmt.QueryRow(idUsuario).Scan(&email)

	if err != nil {
		log.Println("Error querying user", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	isValid, err := argon2.ComparePasswordHash(data.Password, hashedPassword)

	if err != nil {
		log.Println("Error comparing password", err)

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

	err = sendOTPEmail([]string{email}, "loginAdmin "+usuario)

	if err != nil {
		log.Println("Error sending email", err)

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
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var id int

	err = stmt.QueryRow(data.Email).Scan(&id)

	if err != nil {
		log.Println("Error querying user", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	hashedPassword, err := argon2.GenerateHash([]byte(data.Password), argon2.DefaultConfig())

	if err != nil {
		log.Println("Error hashing password", err)

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

func insertProduct(c *gin.Context) {
	var data models.Producto

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	stmt, err := db.DB.Prepare(
		"INSERT INTO Producto (nombre, descripcion, descuento, stock, imagen) VALUES (?, ?, ?, ?, ?, ?);",
	)

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(data.Nombre, data.Descripcion, data.Descuento, data.Stock, data.Imagen)

	if err != nil {
		log.Println("Error inserting product", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error inserting product",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Product inserted successfully",
	})

}
