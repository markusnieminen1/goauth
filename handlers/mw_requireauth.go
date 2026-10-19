package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
)

// RequireAuth rejects the request with 401 unless the token middleware placed a
// validated user ID in the context. It runs after ExtractCookies and ValidateToken.
func RequireAuth(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if UserID(r) == nil {
			WriteErrorHttp(w, customerrors.ErrUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func UserID(r *http.Request) *int64 {

	authCookies, ok := r.Context().Value(AuthCookiesCtxKey{}).(sharedmodels.AuthCookies)

	if !ok {
		return nil
	}

	return authCookies.UserID
}
