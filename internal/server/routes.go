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
		"SELECT id, nombre, descripcion, precio, descuento, stock, imagen, favorito FROM DescProductos WHERE nombre LIKE ? OR descripcion LIKE ?;",
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

	var products []models.DescProducto

	for rows.Next() {
		var product models.DescProducto

		if err := rows.Scan(&product.ID, &product.Nombre, &product.Descripcion, &product.Precio, &product.Descuento, &product.Stock, &product.Imagen, &product.IsFavorite); err != nil {
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

	var products []models.DescProducto

	stmt, err := db.DB.Prepare("SELECT id, nombre, descripcion, precio, descuento, stock, imagen, favorito FROM DescProductos;")

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
		return
	}

	defer rows.Close()

	for rows.Next() {
		var prod models.DescProducto

		err = rows.Scan(&prod.ID, &prod.Nombre, &prod.Descripcion, &prod.Precio, &prod.Descuento, &prod.Stock, &prod.Imagen, &prod.IsFavorite)

		if err != nil {
			log.Println("Error scanning products", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error scanning products",
			})
			return
		}

		products = append(products, prod)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Products retrieved",
		"products": products,
	})

}

func toggleFavorite(c *gin.Context) {

	sess := sessions.Default(c)
	var data models.Favorito

	user := sess.Get("user")

	if err := c.ShouldBindJSON(&data); err != nil {
		log.Println("Error binding json", err)

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error binding json",
		})
		return
	}

	if user == nil {
		log.Println("User not logged in")

		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "User not logged in",
		})
		return
	}

	if data.IDProducto == 0 {
		log.Println("Product ID not provided")

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Product ID not provided",
		})
		return
	}

	stmt, err := db.DB.Prepare("SELECT id FROM Usuario WHERE usuario = ?;")

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var id int

	err = stmt.QueryRow(user.(string)).Scan(&id)

	if err != nil {
		log.Println("Error querying user", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying user",
		})
		return
	}

	data.IDUsuario = id

	stmt, err = db.DB.Prepare("SELECT EXISTS(SELECT * FROM Favorito WHERE idUsuario = ? AND idProducto = ?) AS existe;")

	if err != nil {
		log.Println("Error preparing statement", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error preparing statement",
		})
		return
	}

	defer stmt.Close()

	var exists bool

	err = stmt.QueryRow(id, data.IDProducto).Scan(&exists)

	if err != nil {
		log.Println("Error querying favorite", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error querying favorite",
		})
		return
	}

	if exists {
		if err := unsetFavorite(data); err != nil {
			log.Println("Error removing favorite", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error removing favorite",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Favorite removed",
		})
		return

	} else {
		if err := setFavorite(data); err != nil {
			log.Println("Error adding favorite", err)

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error adding favorite",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Favorite added",
		})

	}

}

func setFavorite(data models.Favorito) error {

	stmt, err := db.DB.Prepare("INSERT INTO Favorito (idProducto, idUsuario) VALUES (?, ?);")

	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(data.IDProducto, data.IDUsuario); err != nil {
		return err
	}

	return nil
}

func unsetFavorite(data models.Favorito) error {

	stmt, err := db.DB.Prepare("DELETE FROM Favorito WHERE idProducto = ? AND idUsuario = ?;")

	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(data.IDProducto, data.IDUsuario); err != nil {
		return err
	}

	return nil
}
