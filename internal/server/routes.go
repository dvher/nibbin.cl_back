package server

import (
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/pkg/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type OTPData struct {
	Tries  int
	Code   *big.Int
	Action string
}

var mailToOTP = make(map[string]OTPData)
var mailToChan = make(map[string]chan any)

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func verifyOTP(c *gin.Context) {

	sess := sessions.Default(c)

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
		log.Println("Error parsing OTP", err)

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

	if strings.HasPrefix(mailToOTP[data.Email].Action, "registerAdmin") {
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
			log.Println("Error preparing statement", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error preparing statement",
			})
			return
		}

		defer stmt.Close()

		_, err = stmt.Exec(id, password)

		if err != nil {
			log.Println("Error inserting admin", err)

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

	if strings.HasPrefix(mailToOTP[data.Email].Action, "login") {
		s := strings.SplitN(mailToOTP[data.Email].Action, " ", 2)

		if len(s) != 2 {
			log.Println("Invalid action")

			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Invalid action",
			})
			return
		}

		if s[1] != "unregistered" {

			user := s[1]

			sess.Set("user", user)
			sess.Set("email", data.Email)
			if err := sess.Save(); err != nil {
				log.Println("Error saving session", err)

				c.JSON(http.StatusInternalServerError, gin.H{
					"message": "Error saving session",
				})
				return
			}
		}
	}

	delete(mailToOTP, data.Email)

	c.JSON(http.StatusOK, gin.H{
		"message": str,
	})
}

func searchProducts(c *gin.Context) {

	search := c.Query("q")

	if search == "" {
		log.Println("Search not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Search not provided",
		})
		return
	}

	stmt, err := db.DB.Prepare(
		"SELECT id, nombre, descripcion, precio, descuento, stock, imagen FROM Producto WHERE nombre LIKE ? OR descripcion LIKE ?;",
	)

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	rows, err := stmt.Query("%"+search+"%", "%"+search+"%")

	if err != nil {
		log.Println("Error querying products", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying products",
		})
		return
	}

	defer rows.Close()

	var products []models.Producto

	for rows.Next() {
		var product models.Producto

		if err := rows.Scan(&product.ID, &product.Nombre, &product.Descripcion, &product.Precio, &product.Descuento, &product.Stock, &product.Imagen); err != nil {
			log.Println("Error scanning products", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error scanning products",
			})
			return
		}

		products = append(products, product)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Products found",
		"products": products,
	})
}

func getProducts(c *gin.Context) {

	var products []models.Producto

	stmt, err := db.DB.Prepare("SELECT id, nombre, descripcion, precio, descuento, stock, imagen FROM Producto;")

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
	}

	defer stmt.Close()

	rows, err := stmt.Query()

	if err != nil {
		log.Println("Error querying products", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying products",
		})
	}

	defer rows.Close()

	for rows.Next() {
		var prod models.Producto

		err = rows.Scan(&prod.ID, &prod.Nombre, &prod.Descripcion, &prod.Precio, &prod.Descuento, &prod.Stock, &prod.Imagen)

		if err != nil {
			log.Println("Error scanning products", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error scanning products",
			})
		}

		products = append(products, prod)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Products retrieved",
		"products": products,
	})

}
