package db

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

// --- Models ---
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Name         string    `json:"name"`
	Email        string    `gorm:"uniqueIndex" json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // "student" or "admin"
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Leave struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	UserID     uint       `json:"user_id"`
	Reason     string     `json:"reason"`
	FromDate   time.Time  `json:"from_date"`
	ToDate     time.Time  `json:"to_date"`
	Status     string     `json:"status"` // PENDING, APPROVED, REJECTED
	HandeledBy string     `json:"handeled_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// --- Init DB & AutoMigrate ---
func InitDB(dsn string) error {
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("connect db: %w", err)
	}
	if err := DB.AutoMigrate(&User{}, &Leave{}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// --- Simple seeding (create sample users) ---
func SeedIfEmpty() error {
	if DB == nil {
		return errors.New("db not initialized")
	}
	var cnt int64
	DB.Model(&User{}).Count(&cnt)
	if cnt > 0 {
		return nil
	}

	create := func(name, email, plainPass, role string) error {
		hash, _ := bcrypt.GenerateFromPassword([]byte(plainPass), bcrypt.DefaultCost)
		u := User{
			Name:         name,
			Email:        email,
			PasswordHash: string(hash),
			Role:         role,
		}
		return DB.Create(&u).Error
	}

	if err := create("Kalyan", "kalyan@example.com", "pass123", "student"); err != nil {
		return err
	}
	if err := create("Alice", "alice@example.com", "pass123", "student"); err != nil {
		return err
	}
	if err := create("Principal", "admin@example.com", "adminpass", "admin"); err != nil {
		return err
	}
	return nil
}


func GetUserByEmail(email string) (*User, error) {
	var user User

	if err := DB.Where("email = ?", email).First(&user).Error; err != nil{
		return nil, err
	}

	return &user, nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))

	return err == nil
}