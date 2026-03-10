package repository

import (
	"your-project/internal/config"
	"your-project/internal/models"
)

type AuthRepository struct{}

func NewAuthRepository() *AuthRepository {
	return &AuthRepository{}
}

func (r *AuthRepository) FindUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := config.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) CreateUser(user *models.User) error {
	return config.DB.Create(user).Error
}

func (r *AuthRepository) FindByUserId(userID uint) (*models.User, error) {
	var user models.User

	if err := config.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *AuthRepository) UpdatePassword(user *models.User, hashedPass string) error {
	return config.DB.Model(user).Update("password", hashedPass).Error
}

func (r *AuthRepository) SaveRefreshToken(storedToken *models.RefreshToken, refreshToken string) error {
	return config.DB.Create(storedToken).Error
}

func (r *AuthRepository) FindValidRefreshToken(token string) (*models.RefreshToken, error) {
	var t models.RefreshToken

	if err := config.DB.Where("token = ? AND revoked = false", token).First(&t).Error; err != nil {
		return nil, err
	}

	return &t, nil
}

func (r *AuthRepository) RevokeRefreshToken(refreshToken *models.RefreshToken) error {
	return config.DB.Model(refreshToken).Update("revoked", true).Error
}

func (r *AuthRepository) RevokeAllRefreshTokensByUserID(userId uint) error {
	return config.DB.Model(&models.RefreshToken{}).
		Where("user_id = ?", userId).
		Update("revoked", true).Error
}

func (r *AuthRepository) BlackListToken(token string) error {
	return config.DB.Create(&models.BlacklistedToken{Token: token}).Error
}
