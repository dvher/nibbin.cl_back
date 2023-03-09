package server

import (
	"log"
	"net/http"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/pkg/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func login(c *gin.Context) {

	var data models.LoginRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

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

	stmt, err := db.DB.Prepare("SELECT usuario FROM Usuario WHERE email = ?")

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var usuario string

	rows, err := stmt.Query(to)

	if err != nil {
		log.Println("Error querying database", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying database",
		})
		return
	}

	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&usuario)

		if err != nil {
			log.Println("Error scanning rows", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error scanning rows",
			})
			return
		}
	}

	action := "login "

	if usuario == "" {
		action += "unregistered"
	} else {
		action += usuario
	}

	err = sendOTPEmail([]string{to}, action)

	if err != nil {
		log.Println("Error sending email", err)

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

	sess := sessions.Default(c)

	puntos := 0

	var data models.RegisterRequest

	if err := c.BindJSON(&data); err != nil {
		log.Println("Error binding json", err)

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	if data.Nombre == "" || data.Apellido == "" || data.Email == "" || data.User == "" || data.Direccion == "" ||
		data.Telefono == "" || data.Nacimiento == "" {
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
		"INSERT INTO Usuario(nombre, apellido, email, usuario, puntos, direccion, telefono, nacimiento) VALUES(?, ?, ?, ?, ?, ?, ?, ?);",
	)

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(data.Nombre, data.Apellido, data.Email, data.User, puntos, data.Direccion, data.Telefono, data.Nacimiento)

	if err != nil {
		log.Println("Error inserting user", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error inserting user",
		})
		return
	}

	sess.Set("user", data.User)
	sess.Set("email", data.Email)
	if err := sess.Save(); err != nil {
		log.Println("Error saving session", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error saving session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created",
	})
}

func logout(c *gin.Context) {
	sess := sessions.Default(c)

	sess.Clear()
	if err := sess.Save(); err != nil {
		log.Println("Error saving session", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error saving session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out",
	})
}
