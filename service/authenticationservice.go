package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	"github.com/markusnieminen1/basic-auth/components/hashing"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/setup"
	"github.com/markusnieminen1/basic-auth/store/session"
	"github.com/markusnieminen1/basic-auth/store/user"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidToken = errors.New("invalid token")

type AuthenticationManagerService struct {
	users    user.Repository
	sessions session.Repository
	tokens   *TokenIssuerService
	hasher   hashing.PasswordHasher
	cache    caching.Store // optional, nil disables session caching

	delayHash string
}

// NewAuthenticationManagerService wires the authentication service. Everything except cache is required.
func NewAuthenticationManagerService(users user.Repository, sessions session.Repository, tokens *TokenIssuerService, hasher hashing.PasswordHasher, cache caching.Store) (*AuthenticationManagerService, error) {

	if users == nil {
		return nil, fmt.Errorf("%w: user repository", ErrMissingDependency)
	}

	if sessions == nil {
		return nil, fmt.Errorf("%w: session repository", ErrMissingDependency)
	}

	if tokens == nil {
		return nil, fmt.Errorf("%w: token issuer", ErrMissingDependency)
	}

	if hasher == nil {
		return nil, fmt.Errorf("%w: password hasher", ErrMissingDependency)
	}

	unknownUserHash, err := hasher.Hash("not existing password")
	if err != nil {
		return nil, fmt.Errorf("auth: preparing the password hasher: %w", err)
	}

	return &AuthenticationManagerService{users: users, sessions: sessions, tokens: tokens, hasher: hasher, cache: cache, delayHash: unknownUserHash}, nil
}

func (a *AuthenticationManagerService) Authenticate(ctx context.Context, cookies sharedmodels.AuthCookies) (int64, error) {

	if cookies.AccessToken == nil {
		return 0, ErrInvalidCredentials
	}

	return a.tokens.ValidateAccessToken(ctx, cookies.AccessToken.Value)
}

func (a *AuthenticationManagerService) Login(ctx context.Context, input sharedmodels.LoginInput) (sharedmodels.AuthCookies, error) {

	var userdata sharedmodels.AllUserProfileAuthData
	var err error

	if input.Email != "" && input.Password != "" {
		userdata, err = a.users.GetByEmail(ctx, input.Email)
	} else if input.Username != "" && input.Password != "" {
		userdata, err = a.users.GetByUsername(ctx, input.Username)
	}

	if errors.Is(err, user.ErrNotFound) {
		_, _ = a.hasher.Verify(input.Password, a.delayHash)

		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}

	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	valid, err := a.hasher.Verify(input.Password, userdata.PasswordHash)
	if err != nil || !valid {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}

	return a.IssueSession(ctx, userdata.UserID)
}

func (a *AuthenticationManagerService) Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error) {

	if cookies.RefreshToken == nil {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}

	tokenHash, err := a.tokens.HashRefreshToken(cookies.RefreshToken.Value)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	stored, err := a.getSession(ctx, tokenHash)
	if errors.Is(err, session.ErrNotFound) {
		return sharedmodels.AuthCookies{}, ErrInvalidToken
	}

	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	revoked, err := a.sessions.Revoke(ctx, tokenHash)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	a.deleteCachedSession(ctx, tokenHash)

	if !revoked {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}

	return a.IssueSession(ctx, stored.UserID)
}

// Logout revokes the session the refresh token by http request
func (a *AuthenticationManagerService) Logout(r *http.Request) (sharedmodels.AuthCookies, error) {

	ctx := r.Context()

	if access, err := r.Cookie(setup.ACCESS_TOKEN_NAME); err == nil {
		if err = a.tokens.RevokeAccessToken(ctx, access.Value, access.Expires); err != nil {
			return sharedmodels.AuthCookies{}, err
		}
	}

	if refresh, err := r.Cookie(setup.REFRESH_TOKEN_NAME); err == nil {
		tokenHash, err := a.tokens.HashRefreshToken(refresh.Value)
		if err != nil {
			return sharedmodels.AuthCookies{}, err
		}

		if _, err = a.sessions.Revoke(ctx, tokenHash); err != nil {
			return sharedmodels.AuthCookies{}, err
		}

		a.deleteCachedSession(ctx, tokenHash)
	}

	return expiredCookies(), nil
}

func (a *AuthenticationManagerService) LogoutAll(ctx context.Context, userID int64) error {
	return a.sessions.RevokeAllForUser(ctx, userID)
}

func (a *AuthenticationManagerService) IssueSession(ctx context.Context, userID int64) (sharedmodels.AuthCookies, error) {

	accessToken, accessExpiresAt, err := a.tokens.IssueAccessToken(ctx, userID)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	refreshToken, refreshExpiresAt, err := a.tokens.IssueRefreshToken(ctx)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	refreshHash, err := a.tokens.HashRefreshToken(refreshToken)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	if err = a.sessions.Create(ctx, session.Session{UserID: userID, RefreshTokenHash: refreshHash, ValidUntil: refreshExpiresAt}); err != nil {
		return sharedmodels.AuthCookies{}, err
	}

	return sharedmodels.AuthCookies{
		AccessToken:  newCookie(setup.ACCESS_TOKEN_NAME, accessToken, accessExpiresAt),
		RefreshToken: newCookie(setup.REFRESH_TOKEN_NAME, refreshToken, refreshExpiresAt),
		UserID:       &userID,
	}, nil
}

func (a *AuthenticationManagerService) getSession(ctx context.Context, tokenHash string) (session.Session, error) {

	if a.cache != nil {
		data, err := a.cache.Get(ctx, refreshSessionKey(tokenHash))
		if err == nil {
			var cached session.Session
			if err = json.Unmarshal(data, &cached); err != nil {
				return session.Session{}, err
			}

			return cached, nil
		}

		if !errors.Is(err, caching.ErrMiss) {
			return session.Session{}, err
		}
	}

	storedSession, err := a.sessions.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return session.Session{}, err
	}

	if a.cache != nil {
		if data, marshalErr := json.Marshal(storedSession); marshalErr == nil {
			_ = a.cache.Set(ctx, refreshSessionKey(tokenHash), data, time.Until(storedSession.ValidUntil))
		}
	}

	return storedSession, nil
}

func (a *AuthenticationManagerService) deleteCachedSession(ctx context.Context, tokenHash string) {

	if a.cache != nil {
		_ = a.cache.Delete(ctx, refreshSessionKey(tokenHash))
	}
}

// newCookie builds an auth cookie from the cookie settings in setup.
func newCookie(name, value string, expires time.Time) *http.Cookie {

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     setup.COOKIE_PATH,
		Domain:   setup.COOKIE_DOMAIN,
		Expires:  expires,
		HttpOnly: setup.COOKIE_HTTPONLY,
		Secure:   setup.COOKIE_SECURE,
		SameSite: cookieSameSite(),
	}
}

func cookieSameSite() http.SameSite {

	switch strings.ToLower(setup.COOKIE_SAMESITE) {
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

func expiredCookies() sharedmodels.AuthCookies {
	expire := func(name string) *http.Cookie {
		c := newCookie(name, "", time.Unix(0, 0))
		c.MaxAge = -1

		return c
	}

	return sharedmodels.AuthCookies{AccessToken: expire(setup.ACCESS_TOKEN_NAME), RefreshToken: expire(setup.REFRESH_TOKEN_NAME)}
}

func refreshSessionKey(tokenHash string) string {
	return "auth:refresh-session:" + tokenHash
}

func accessBlacklistKey(token string) string {
	return "auth:access-blacklist:" + token
}

var _ AuthenticationService = (*AuthenticationManagerService)(nil)

var _ Authenticator = (*AuthenticationManagerService)(nil)
