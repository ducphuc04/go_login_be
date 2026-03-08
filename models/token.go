package models

import (
	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	UserID    uint   `gorm:"not null; index"`
	Token     string `gorm:"uniqueIndex;not null"`
	ExpiresAt int64  `gorm:"not null"`
	Revoked   bool   `gorm:"default:false"`
}

type BlacklistedToken struct {
	gorm.Model
	Token string `gorm:"uniqueIndex; not null"`
}
