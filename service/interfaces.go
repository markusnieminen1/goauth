package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/markusnieminen1/goauth/domain/sharedmodels"
)

var ErrMissingDependency = errors.New("missing required dependency")

// AccountService is responsible for user accounts
type AccountService interface {
	Register(ctx context.Context, input sharedmodels.RegisterInput) (cookies sharedmodels.AuthCookies, err error)
	GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error)
	UpdateEmail(ctx context.Context, input sharedmodels.UpdateEmailInput) (sharedmodels.LimitedUserAuthData, error)
	UpdateUsername(ctx context.Context, input sharedmodels.UpdateUsernameInput) (sharedmodels.LimitedUserAuthData, error)
	ChangePassword(ctx context.Context, input sharedmodels.ChangePasswordInput) error
	Delete(ctx context.Context, userID int64) error
}

// AuthenticationService is responsible for user sessions
type AuthenticationService interface {
	Login(ctx context.Context, input sharedmodels.LoginInput) (sharedmodels.AuthCookies, error)
	Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error)

	Logout(r *http.Request) (sharedmodels.AuthCookies, error)
	LogoutAll(ctx context.Context, userID int64) error
}

type SessionIssuer interface {
	IssueSession(ctx context.Context, userID int64) (sharedmodels.AuthCookies, error)
}

type Authenticator interface {
	Authenticate(ctx context.Context, cookies sharedmodels.AuthCookies) (userID int64, err error)
	Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error)
}

/*
Login:
Check password + username -> cookies

Logout:
expire refresh and session -> cookies

Register:
Validate, Save data -> cookies

General use:
Validate -> cookies
Validate -> cookies

*/
