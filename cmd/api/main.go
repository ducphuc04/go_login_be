package main

import (
	"log"
	"your-project/internal/config"
	"your-project/internal/handlers"
	"your-project/internal/middleware"
	models2 "your-project/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Not found .env")
	}

	config.InitDB()

	err := config.DB.AutoMigrate(&models2.User{}, &models2.RefreshToken{}, &models2.BlacklistedToken{})
	if err != nil {
		return
	}
	r := gin.Default()

	users := r.Group("/api/v1/users")
	{
		users.POST("", handlers.Register)
	}

	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/token", handlers.Login)
		auth.PUT("/token", handlers.RefreshToken)
		//auth.DELETE("/token", handlers.Logout)
	}

	protected := r.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/users/me", handlers.GetMe)
		protected.DELETE("/auth/token", handlers.Logout)
		protected.DELETE("/auth/token/all", handlers.LogoutAllDevice)
		protected.PATCH("/users/me/password", handlers.ChangePassword)
	}

	r.Run(":8080")
}
