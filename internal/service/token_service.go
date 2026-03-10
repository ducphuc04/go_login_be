package service

import (
	"os"
	"time"
	"your-project/internal/config"
	"your-project/internal/middleware"
	models2 "your-project/internal/models"
	"your-project/internal/repository"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
	authRepo *repository.AuthRepository
}

func NewTokenService(authRepo *repository.AuthRepository) *TokenService {
	return &TokenService{authRepo: authRepo}
}

func (s *TokenService) generateAccessToken(user models2.User) (string, error) {
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

// AI
func (s *TokenService) generateRefreshToken(user models2.User) (string, error) {
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

	config.DB.Create(&models2.RefreshToken{
		UserID:    user.ID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
	})

	return tokenStr, nil
}
