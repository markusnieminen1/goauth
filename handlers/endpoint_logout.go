package handlers

import (
	"net/http"

	"github.com/markusnieminen1/goauth/domain/customerrors"
	"github.com/markusnieminen1/goauth/service"
)

type LogoutHandler struct {
	AuthenticationService service.AuthenticationService
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		WriteErrorHttp(w, customerrors.ErrMethodNotApplicable)

		return
	}

	expired, err := h.AuthenticationService.Logout(r)
	if err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)

		return
	}

	http.SetCookie(w, expired.AccessToken)
	http.SetCookie(w, expired.RefreshToken)
	w.WriteHeader(http.StatusOK)
}
