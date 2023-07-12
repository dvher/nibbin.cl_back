package server

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dvher/nibbin.cl_back/internal/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	csrf "github.com/utrack/gin-csrf"
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
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	store := cookie.NewStore([]byte(os.Getenv("SESSION_KEY")), []byte(os.Getenv("SESSION_ENC")))

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   false,
		Domain:   "localhost",
	})

	r.Use(sessions.Sessions("nibbinSession", store))

	r.Use(csrf.Middleware(csrf.Options{
		Secret: os.Getenv("CSRF_SECRET"),
		ErrorFunc: func(c *gin.Context) {

			log.Println("CSRF token mismatch")

			c.JSON(http.StatusBadRequest, gin.H{
				"error": "CSRF token mismatch",
			})
			c.Abort()
		},
		TokenGetter: func(c *gin.Context) string {

			sess := sessions.Default(c)

			token := sess.Get("X-CSRF-Token")

			if token == nil {
				token = csrf.GetToken(c)
				sess.Set("X-CSRF-Token", token)
				if err := sess.Save(); err != nil {
					log.Println("Error saving session", err)
				}
			}

			return token.(string)
		},
	}))

	r.SetTrustedProxies(nil)

	public := r.Group("/")

	public.GET("/", ping)
	public.GET("/islogged", isLogged)
	public.GET("/product/search", searchProducts)
	public.GET("/product", getProducts)
	public.GET("/product/:id", getProduct)
	public.POST("/login", login)
	public.POST("/verify", verifyOTP)
	public.POST("/register", register)
	public.PUT("/togglefavorite", toggleFavorite)
	public.DELETE("/logout", logout)

	private := r.Group("/admin")

	private.Use(middleware.Auth())

	private.POST("/product", insertProduct)
	private.POST("/login", loginAdmin)
	private.POST("/register", registerAdmin)

	log.Println("Server started")

	return r
}
