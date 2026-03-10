package service

import (
	"errors"
	"os"
	"time"
	"your-project/internal/middleware"
	"your-project/internal/models"
	"your-project/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	authRepo     *repository.AuthRepository
	tokenService *TokenService
}

func NewAuthService() *AuthService {
	authRepo := repository.NewAuthRepository()
	return &AuthService{authRepo: authRepo, tokenService: NewTokenService(authRepo)}
}

func (r *AuthService) Register(req models.RegisterRequest) error {
	if req.Password != req.ConfirmPassword {
		return errors.New("password mismatch")
	}

	_, err := r.authRepo.FindUserByEmail(req.Email)

	if err == nil {
		return errors.New("email already exists")
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	user := &models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashed),
	}

	if err := r.authRepo.CreateUser(user); err != nil {
		return err
	}

	return nil
}

func (r *AuthService) Login(req models.LoginRequest) (string, string, error) {
	var user *models.User

	user, err := r.authRepo.FindUserByEmail(req.Email)

	if err != nil {
		return "", "", errors.New("email is not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return "", "", errors.New("password not match")
	}

	accessToken, errAccess := r.tokenService.generateAccessToken(*user)
	refreshToken, errRefresh := r.tokenService.generateRefreshToken(*user)

	if errAccess != nil {
		return "", "", errors.New("error: Access Token faces bug")
	}

	if errRefresh != nil {
		return "", "", errors.New("error: Refresh Token faces bug")
	}

	return accessToken, refreshToken, nil
}

func (r *AuthService) Logout(rawToken string) error {
	return r.authRepo.BlackListToken(rawToken)
}

func (r *AuthService) RefreshToken(refreshToken string) (string, string, error) {
	claims := &middleware.Claims{}

	token, err := jwt.ParseWithClaims(refreshToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return "", "", errors.New("unauthorized")
	}

	storedToken, err := r.authRepo.FindValidRefreshToken(refreshToken)

	if err != nil {
		return "", "", errors.New("refresh token is invalid")
	}

	if time.Now().Unix() > storedToken.ExpiresAt {
		return "", "", errors.New("refresh token is expired")
	}

	user, err := r.authRepo.FindByUserId(storedToken.UserID)
	if err != nil {
		return "", "", errors.New("user not found")
	}

	if err := r.authRepo.RevokeRefreshToken(storedToken); err != nil {
		return "", "", err
	}

	newAccessToken, err := r.tokenService.generateAccessToken(*user)
	if err != nil {
		return "", "", err
	}
	newRefreshToken, err := r.tokenService.generateRefreshToken(*user)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (r *AuthService) ChangePassword(userID uint, req models.ChangePasswordRequest) error {
	if req.NewPassword != req.ConfirmPassword {
		return errors.New("password mismatch")
	}

	user, err := r.authRepo.FindByUserId(userID)

	if err != nil {
		return errors.New("not found user")
	}

	//log.Fatalf("password: %v", req.OldPassword)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		return errors.New("old password is wrong")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := r.authRepo.UpdatePassword(user, string(hashed)); err != nil {
		return err
	}

	return nil
}

func (r *AuthService) LogOutAllDevice(userID uint, rawToken string) error {
	if err := r.authRepo.RevokeAllRefreshTokensByUserID(userID); err != nil {
		return err
	}

	return r.authRepo.BlackListToken(rawToken)
}

func (r *AuthService) GetMe(userID uint) (*models.UserResponse, error) {
	user, err := r.authRepo.FindByUserId(userID)
	if err != nil {
		return nil, err
	}

	response := user.ToUserResponse()
	return &response, nil
}
