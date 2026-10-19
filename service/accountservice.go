package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/markusnieminen1/goauth/components/hashing"
	"github.com/markusnieminen1/goauth/domain/sharedmodels"
	"github.com/markusnieminen1/goauth/internal/validating"
	"github.com/markusnieminen1/goauth/store/session"
	"github.com/markusnieminen1/goauth/store/user"
)

type AccountManagerService struct {
	validator validating.UserDataValidator
	users     user.Repository
	sessions  session.Repository
	hasher    hashing.PasswordHasher

	sessionIssuer SessionIssuer
}

// NewAccountManagerService wires the account service. Everything is required.
// Sessions are needed to end them when the password changes or the account is deleted.
func NewAccountManagerService(users user.Repository, sessions session.Repository, hasher hashing.PasswordHasher, sessionIssuer SessionIssuer) (*AccountManagerService, error) {

	if users == nil {
		return nil, fmt.Errorf("%w: user repository", ErrMissingDependency)
	}

	if sessions == nil {
		return nil, fmt.Errorf("%w: session repository", ErrMissingDependency)
	}

	if hasher == nil {
		return nil, fmt.Errorf("%w: password hasher", ErrMissingDependency)
	}

	if sessionIssuer == nil {
		return nil, fmt.Errorf("%w: session issuer", ErrMissingDependency)
	}

	return &AccountManagerService{
		validator: validating.NewUserValidatorDefaultSetup(),
		users:     users,
		sessions:  sessions,
		hasher:    hasher,

		sessionIssuer: sessionIssuer,
	}, nil
}

func (u *AccountManagerService) Register(ctx context.Context, input sharedmodels.RegisterInput) (sharedmodels.AuthCookies, error) {

	input.Email = normalisedIdentifier(input.Email)
	input.Username = normalisedIdentifier(input.Username)

	if err := u.validator.ValidateEmail(input.Email); err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	if err := u.validator.ValidatePassword(input.Password); err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	if err := u.validator.ValidateUsername(input.Username); err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	passwordHash, err := u.hasher.Hash(input.Password)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	userID, err := u.users.Create(ctx, sharedmodels.AllUserProfileAuthData{
		Email:        input.Email,
		Username:     input.Username,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	cookies, err := u.sessionIssuer.IssueSession(ctx, userID)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	return cookies, nil
}

func (u *AccountManagerService) GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error) {

	if err := u.validator.ValidateUserID(userID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	return u.users.GetByID(ctx, userID)
}

func (u *AccountManagerService) UpdateEmail(ctx context.Context, input sharedmodels.UpdateEmailInput) (sharedmodels.LimitedUserAuthData, error) {

	input.Email = normalisedIdentifier(input.Email)

	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.validator.ValidateEmail(input.Email); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.verifyPassword(ctx, input.UserID, input.Password); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.users.UpdateEmail(ctx, input.UserID, input.Email); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	return u.GetByID(ctx, input.UserID)
}

func (u *AccountManagerService) UpdateUsername(ctx context.Context, input sharedmodels.UpdateUsernameInput) (sharedmodels.LimitedUserAuthData, error) {

	input.Username = normalisedIdentifier(input.Username)

	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.validator.ValidateUsername(input.Username); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.verifyPassword(ctx, input.UserID, input.Password); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	if err := u.users.UpdateUsername(ctx, input.UserID, input.Username); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	return u.GetByID(ctx, input.UserID)
}

func (u *AccountManagerService) ChangePassword(ctx context.Context, input sharedmodels.ChangePasswordInput) error {

	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return err
	}

	if err := u.validator.ValidatePassword(input.Replacement); err != nil {
		return err
	}

	if err := u.verifyPassword(ctx, input.UserID, input.Current); err != nil {
		return err
	}

	newHash, err := u.hasher.Hash(input.Replacement)

	if err != nil {
		return err
	}

	if err = u.users.UpdatePasswordHash(ctx, input.UserID, newHash); err != nil {
		return err
	}

	if err = u.sessions.RevokeAllForUser(ctx, input.UserID); err != nil {
		return fmt.Errorf("password changed, but ending existing sessions failed: %w", err)
	}

	return nil
}

func (u *AccountManagerService) verifyPassword(ctx context.Context, userID int64, plain string) error {

	credentials, err := u.users.GetCredentialsByID(ctx, userID)

	if err != nil {
		return err
	}

	valid, err := u.hasher.Verify(plain, credentials.PasswordHash)

	if err != nil {
		return err
	}

	if !valid {
		return ErrInvalidCredentials
	}

	return nil
}

func (u *AccountManagerService) Delete(ctx context.Context, userID int64) error {

	if err := u.validator.ValidateUserID(userID); err != nil {
		return err
	}

	if err := u.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}

	return u.users.Delete(ctx, userID)
}

var _ AccountService = (*AccountManagerService)(nil)

func normalisedIdentifier(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
