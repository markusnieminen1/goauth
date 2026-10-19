package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
)

type RegisterHandler struct {
	AccountService service.AccountService
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		WriteErrorHttp(w, customerrors.ErrMethodNotApplicable)

		return
	}

	var input sharedmodels.RegisterInput
	if err := GeneralDecoder(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	cookies, err := h.AccountService.Register(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)

		return
	}

	if cookies.AccessToken != nil {
		http.SetCookie(w, cookies.AccessToken)
	}

	if cookies.RefreshToken != nil {
		http.SetCookie(w, cookies.RefreshToken)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]int64{"user_id": *cookies.UserID})
}
