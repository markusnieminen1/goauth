package user

import (
	"context"
	"errors"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already taken")
	ErrEmailTaken    = errors.New("email already taken")
)

type Repository interface {
	Create(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (userID int64, err error)
	GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error)
	GetCredentialsByID(ctx context.Context, userID int64) (sharedmodels.AllUserProfileAuthData, error)
	GetByUsername(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error)
	GetByEmail(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error)

	UpdateEmail(ctx context.Context, userID int64, email string) error
	UpdateUsername(ctx context.Context, userID int64, username string) error
	UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error

	Delete(ctx context.Context, userID int64) error
}
