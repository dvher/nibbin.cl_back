package server

import (
	"log"
	"os"
	"time"

	"github.com/dvher/nibbin.cl_back/internal/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

/*
* When on production, change AlowOrigins to the domain of the front-end
* and store.Options.Secure to true
 */

func New() *gin.Engine {

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://nibbin.cl:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	store := cookie.NewStore([]byte(os.Getenv("SESSION_KEY")), []byte(os.Getenv("SESSION_ENC")))

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   false,
		Domain:   "localhost",
	})

	r.Use(sessions.Sessions("nibbinSession", store))

	r.SetTrustedProxies(nil)

	public := r.Group("/")

	public.GET("/", ping)
	public.GET("/islogged", isLogged)
	public.GET("/searchproducts", searchProducts)
	public.GET("/getproducts", getProducts)
	public.POST("/login", login)
	public.POST("/verify", verifyOTP)
	public.POST("/register", register)
	public.DELETE("/logout", logout)

	private := r.Group("/admin")

	private.Use(middleware.Auth())

	private.POST("/insertproduct", insertProduct)
	private.POST("/login", loginAdmin)
	private.POST("/register", registerAdmin)

	log.Println("Server started")

	return r
}
