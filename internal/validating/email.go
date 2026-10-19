package validating

import (
	"net/mail"

	"github.com/markusnieminen1/goauth/domain/customerrors"
	"github.com/markusnieminen1/goauth/setup"
)

func (u *UserDataValidator) ValidateEmail(trimmedEmail string) error {

	if trimmedEmail == "" {
		return customerrors.ErrEmailEmpty
	}

	if len(trimmedEmail) > setup.Email_MaxLength {
		return customerrors.ErrEmailTooLong
	}

	// ParseAddress also accepts "Name <a@b.com>", but only the bare address may be stored.
	parsed, err := mail.ParseAddress(trimmedEmail)
	if err != nil || parsed.Address != trimmedEmail {
		return customerrors.ErrEmailInvalid
	}

	return nil
}
