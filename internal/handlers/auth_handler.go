package handlers

import (
	"net/http"
	"your-project/internal/models"
	"your-project/internal/service"

	"github.com/gin-gonic/gin"
)

var authService = service.NewAuthService()

func Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := authService.Register(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully",
	})
}

// KH AI
func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, err := authService.Login(req)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Kh AI
func Logout(c *gin.Context) {
	rawToken, exists := c.Get("raw_token")

	if !exists || rawToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not found token"})
		return
	}

	tokenStr, ok := rawToken.(string)

	if !ok || tokenStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token is invalid"})
		return
	}

	if err := authService.Logout(tokenStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successfully",
	})

}

// AI
func RefreshToken(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	newAccessToken, newRefreshToken, err := authService.RefreshToken(body.RefreshToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

// Kh AI
func ChangePassword(c *gin.Context) {
	userID := c.GetUint("user_id")

	var req models.ChangePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := authService.ChangePassword(userID, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// AI
func LogoutAllDevice(c *gin.Context) {
	userID := c.GetUint("user_id")

	rawToken, exists := c.Get("raw_token")
	if !exists || rawToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not found token"})
		return
	}

	tokenStr, ok := rawToken.(string)
	if !ok || tokenStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token is invalid"})
		return
	}

	if err := authService.LogOutAllDevice(userID, tokenStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout all device successfully"})
}

// Kh AI
func GetMe(c *gin.Context) {
	userID := c.GetUint("user_id")

	response, err := authService.GetMe(userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
