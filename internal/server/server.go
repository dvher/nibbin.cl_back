package server

import (
	"log"

	"github.com/gin-gonic/gin"
)

func New() *gin.Engine {

	r := gin.Default()

	r.GET("/", ping)

	log.Println("Server started")

	return r
}
