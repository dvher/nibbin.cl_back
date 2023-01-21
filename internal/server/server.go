package server

import (
	"log"

	"github.com/gin-gonic/gin"
)

func New() *gin.Engine {

	r := gin.Default()

	r.GET("/", ping)
	r.POST("/login", login)
	r.POST("/verify", verifyOTP)

	log.Println("Server started")

	return r
}
