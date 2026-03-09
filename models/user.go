package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name     string `gorm:"not null" json:"name"`
	Email    string `gorm:"uniqueIndex;not null" json:"email"`
	Password string `gorm:"not null" json:"-"`
}

type RegisterRequest struct {
	Name            string `json:"name" binding:"required,min=6"`
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirmPassword" binding:"required,min=8,eqfield=Password"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type ChangePasswordRequest struct {
	OldPassword     string `json:"old-password" binding:"required,min=8"`
	NewPassword     string `json:"new-password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm-password" binding:"required,min=8,eqfield=NewPassword"`
}

type UserResponse struct {
	UserId uint   `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

func (u *User) ToUserResponse() UserResponse {
	return UserResponse{
		UserId: u.ID,
		Name:   u.Name,
		Email:  u.Email,
	}
}
