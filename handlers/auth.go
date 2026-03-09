package handlers

import (
	"log"
	"net/http"
	"os"
	"time"
	"your-project/config"
	"your-project/middleware"
	"your-project/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func generateAccessToken(user models.User) (string, error) {
	claims := middleware.Claims{
		UserID: int(user.ID),
		Email:  user.Email,
		Name:   user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func generateRefreshToken(user models.User) (string, error) {
	claims := middleware.Claims{
		UserID: int(user.ID),
		Email:  user.Email,
		Name:   user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}

	config.DB.Create(&models.RefreshToken{
		UserID:    user.ID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
	})

	return tokenStr, nil
}

func Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if req.Password != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
		return
	}

	user := models.User{Name: req.Name, Email: req.Email, Password: string(hashed)}

	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	}

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully",
	})
}

func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email is not correct"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Password is not correct"})
		return
	}

	accessToken, _ := generateAccessToken(user)
	refreshToken, _ := generateRefreshToken(user)
	c.JSON(http.StatusOK, gin.H{
		"token":         accessToken,
		"refresh_token": refreshToken,
	})
}

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

	config.DB.Create(&models.BlacklistedToken{Token: tokenStr})

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successfully",
	})

}

func RefreshToken(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var storedToken models.RefreshToken
	if err := config.DB.Where("token = ? AND revoked = false", body.RefreshToken).First(&storedToken).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is not valid"})
		return
	}

	if time.Now().Unix() > storedToken.ExpiresAt {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is expired"})
		return
	}

	var user models.User
	if err := config.DB.First(&user, storedToken.UserID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not found user"})
		return
	}

	config.DB.Model(&storedToken).Update("revoked", true)

	newAccessToken, _ := generateAccessToken(user)
	newRefreshToken, _ := generateRefreshToken(user)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func ChangePassword(c *gin.Context) {
	userID := c.GetUint("user_id")

	var user models.User

	log.Printf("userID: %v", userID)
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found user"})
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Old password is not correct"})
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password mismatch"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	config.DB.Model(&user).Update("password", string(hashed))

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func LogoutAllDevice(c *gin.Context) {
	userID := c.GetUint("user_id")

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

	if err := config.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked = false", userID).
		Update("revoked", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := config.DB.Create(&models.BlacklistedToken{Token: tokenStr}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout all device successfully"})

}

func GetMe(c *gin.Context) {
	userID := c.GetUint("user_id")

	var user models.User

	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found user"})
		return
	}

	log.Printf("user từ DB: %+v", user)
	log.Printf("response: %+v", user.ToUserResponse())

	c.JSON(http.StatusOK, user.ToUserResponse())
}
