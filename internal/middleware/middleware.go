package middleware

import (
	"net/http"

	db "github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		email := session.Get("email")

		stmt, err := db.DB.Prepare("SELECT id FROM Usuario WHERE usuario = ? AND email = ?;")

		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		defer stmt.Close()

		var id int

		err = stmt.QueryRow(user, email).Scan(&id)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		stmt, err = db.DB.Prepare("SELECT id FROM Admin WHERE idUsuario = ?;")

		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		defer stmt.Close()

		err = stmt.QueryRow(id).Scan(&id)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}
