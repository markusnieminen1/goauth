package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/markusnieminen1/goauth/components/token"
	"github.com/markusnieminen1/goauth/domain/sharedmodels"
	"github.com/markusnieminen1/goauth/service"
)

// NewValidateTokenMiddleware sets AuthCookies.UserID in the context when the request is
// authenticated.
func NewValidateTokenMiddleware(authenticator service.Authenticator) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authCookieCtx, ok := r.Context().Value(AuthCookiesCtxKey{}).(sharedmodels.AuthCookies)

			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			if authCookieCtx.AccessToken != nil {
				if userID, err := authenticator.Authenticate(r.Context(), authCookieCtx); err == nil {
					authCookieCtx.UserID = &userID
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthCookiesCtxKey{}, authCookieCtx)))
					return

				} else if err != nil && errors.Is(err, token.ErrInvalidToken) {
					// Revoke both tokens if data has been corrupted (or edited)
					// http.SetCookie(w, expired token)
					// http.SetCookie(w, expired token)
					next.ServeHTTP(w, r)
					return
				}

			}

			if authCookieCtx.RefreshToken == nil {
				next.ServeHTTP(w, r)
				return
			}

			refreshedSession, err := authenticator.Refresh(r.Context(), authCookieCtx)
			if err != nil {

				if errors.Is(err, token.ErrInvalidToken) {
					// Revoke both tokens if data has been corrupted (or edited)
					// http.SetCookie(w, expired token)
					// http.SetCookie(w, expired token)
				}

				next.ServeHTTP(w, r)
				return
			}

			if refreshedSession.AccessToken != nil {
				http.SetCookie(w, refreshedSession.AccessToken)
			}

			if refreshedSession.RefreshToken != nil {
				http.SetCookie(w, refreshedSession.RefreshToken)
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthCookiesCtxKey{}, refreshedSession)))
		})

	}
}
