package validating

import (
	"errors"
	"strings"
	"testing"

	"github.com/markusnieminen1/goauth/domain/customerrors"
	"github.com/markusnieminen1/goauth/setup"
)

func TestPasswordForbiddenChars(t *testing.T) {

	v := NewUserValidatorDefaultSetup()
	v.passwordrules.ForbiddenChars = " <>"

	for _, bad := range []string{"Sup3r secret!", "Sup3r-secret!<", "Sup3r>secret!"} {
		if err := v.ValidatePassword(bad); !errors.Is(err, customerrors.ErrPasswordForbiddenChar) {
			t.Errorf("%q: got %v, want ErrPasswordForbiddenChar", bad, err)
		}
	}

	if err := v.ValidatePassword("Sup3r-secret!"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}

	v.passwordrules.ForbiddenChars = ""
	if err := v.ValidatePassword("Sup3r secret!"); err != nil {
		t.Errorf("with nothing forbidden a space is fine, got %v", err)
	}
}

func TestPasswordDefaultsForbidSpaces(t *testing.T) {

	setup.PWD_ForbiddenChars = " "
	v := NewUserValidatorDefaultSetup()
	if err := v.ValidatePassword("Sup3r secret!"); !errors.Is(err, customerrors.ErrPasswordForbiddenChar) {
		t.Errorf("got %v, want ErrPasswordForbiddenChar", err)
	}
}

func TestUsernameForbiddenChars(t *testing.T) {

	v := NewUserValidatorDefaultSetup()
	v.usernamerules.ForbiddenChars = "-x"

	for _, bad := range []string{"al-ice", "alxce"} {
		if err := v.ValidateUsername(bad); !errors.Is(err, customerrors.ErrUsernameForbiddenChar) {
			t.Errorf("%q: got %v, want ErrUsernameForbiddenChar", bad, err)
		}
	}

	// "_" is allowed by the character rules and not forbidden, so it still passes.
	if err := v.ValidateUsername("al_ice"); err != nil {
		t.Errorf("valid username rejected: %v", err)
	}

	// Characters outside the allowed set keep their own error.
	if err := v.ValidateUsername("al ice"); !errors.Is(err, customerrors.ErrUsernameInvalidChar) {
		t.Errorf("got %v, want ErrUsernameInvalidChar", err)
	}
}

// rules used by the table tests, independent of the setup package defaults.
func testValidator() UserDataValidator {

	return UserDataValidator{
		passwordrules: PasswordRules{
			MinLength:      8,
			MaxLength:      72,
			MinUppercase:   1,
			MinLowercase:   1,
			MinDigits:      1,
			MinSymbols:     1,
			ForbiddenChars: " ",
		},
		usernamerules: UsernameRules{
			MinLength:         3,
			MaxLength:         10,
			AllowSpecialChars: true,
			ForbiddenChars:    " ",
		},
	}
}

func TestUserDataValidator_ValidateEmail(t *testing.T) {

	tooLong := strings.Repeat("a", 250) + "@b.co"

	tests := []struct {
		name    string
		email   string
		wantErr error
	}{
		{name: "valid", email: "alice@example.com"},
		{name: "valid with plus tag", email: "alice+tag@example.com"},
		{name: "surrounding space is trimmed", email: "  alice@example.com  "},
		{name: "empty", email: "", wantErr: customerrors.ErrEmailEmpty},
		{name: "only spaces", email: "   ", wantErr: customerrors.ErrEmailEmpty},
		{name: "too long", email: tooLong, wantErr: customerrors.ErrEmailTooLong},
		{name: "no at sign", email: "alice.example.com", wantErr: customerrors.ErrEmailInvalid},
		{name: "no domain", email: "alice@", wantErr: customerrors.ErrEmailInvalid},
		{name: "display name is not a bare address", email: "Alice <alice@example.com>", wantErr: customerrors.ErrEmailInvalid},
		{name: "two addresses", email: "a@example.com, b@example.com", wantErr: customerrors.ErrEmailInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()

			if err := v.ValidateEmail(tt.email); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateEmail(%q) error = %v, want %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestUserDataValidator_ValidatePassword(t *testing.T) {

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{name: "valid", password: "Sup3r-secret!"},
		{name: "exactly minimum length", password: "Abcde1!x"},
		{name: "exactly maximum length", password: "Aa1!" + strings.Repeat("x", 68)},
		{name: "empty", password: "", wantErr: customerrors.ErrPasswordEmpty},
		{name: "forbidden space", password: "Sup3r secret!", wantErr: customerrors.ErrPasswordForbiddenChar},
		{name: "too short", password: "Ab1!", wantErr: customerrors.ErrPasswordTooShort},
		{name: "too long", password: "Aa1!" + strings.Repeat("x", 69), wantErr: customerrors.ErrPasswordTooLong},
		{name: "no uppercase", password: "sup3r-secret!", wantErr: customerrors.ErrPasswordNeedsUpper},
		{name: "no lowercase", password: "SUP3R-SECRET!", wantErr: customerrors.ErrPasswordNeedsLower},
		{name: "no digit", password: "Super-secret!", wantErr: customerrors.ErrPasswordNeedsDigit},
		{name: "no symbol", password: "Sup3rsecret", wantErr: customerrors.ErrPasswordNeedsSymbol},
		{name: "unicode letters count", password: "Ääkköset1!", wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()

			if err := v.ValidatePassword(tt.password); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidatePassword(%q) error = %v, want %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestUserDataValidator_ValidatePassword_RuleCounts(t *testing.T) {

	tests := []struct {
		name     string
		mutate   func(r *PasswordRules)
		password string
		wantErr  error
	}{
		{name: "two uppercase needed, one given", mutate: func(r *PasswordRules) { r.MinUppercase = 2 }, password: "Sup3r-secret!", wantErr: customerrors.ErrPasswordNeedsUpper},
		{name: "two uppercase needed, two given", mutate: func(r *PasswordRules) { r.MinUppercase = 2 }, password: "SUp3r-secret!"},
		{name: "no requirements", mutate: func(r *PasswordRules) { *r = PasswordRules{MaxLength: 72} }, password: "x"},
		{name: "forbidden chars list", mutate: func(r *PasswordRules) { r.ForbiddenChars = "<>" }, password: "Sup3r>secret!", wantErr: customerrors.ErrPasswordForbiddenChar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()
			tt.mutate(&v.passwordrules)

			if err := v.ValidatePassword(tt.password); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidatePassword(%q) error = %v, want %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestUserDataValidator_ValidateUsername(t *testing.T) {

	tests := []struct {
		name     string
		username string
		wantErr  error
	}{
		{name: "valid", username: "alice"},
		{name: "digits", username: "alice99"},
		{name: "underscore and hyphen allowed", username: "al_i-ce"},
		{name: "unicode letters", username: "äiti"},
		{name: "surrounding space is trimmed", username: "  alice  "},
		{name: "exactly minimum length", username: "abc"},
		{name: "exactly maximum length", username: "abcdefghij"},
		{name: "length counts runes, not bytes", username: "ääääääääää"},
		{name: "empty", username: "", wantErr: customerrors.ErrUsernameEmpty},
		{name: "only spaces", username: "   ", wantErr: customerrors.ErrUsernameEmpty},
		{name: "too short", username: "ab", wantErr: customerrors.ErrUsernameTooShort},
		{name: "too long", username: "abcdefghijk", wantErr: customerrors.ErrUsernameTooLong},
		{name: "forbidden inner space", username: "al ice", wantErr: customerrors.ErrUsernameForbiddenChar},
		{name: "invalid character", username: "al!ce", wantErr: customerrors.ErrUsernameInvalidChar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()

			if err := v.ValidateUsername(tt.username); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateUsername(%q) error = %v, want %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestUserDataValidator_ValidateUsername_SpecialCharsDisabled(t *testing.T) {

	tests := []struct {
		name     string
		username string
		wantErr  error
	}{
		{name: "underscore rejected", username: "al_ice", wantErr: customerrors.ErrUsernameInvalidChar},
		{name: "hyphen rejected", username: "al-ice", wantErr: customerrors.ErrUsernameInvalidChar},
		{name: "alphanumeric accepted", username: "alice1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()
			v.usernamerules.AllowSpecialChars = false

			if err := v.ValidateUsername(tt.username); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateUsername(%q) error = %v, want %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestUserDataValidator_ValidateUserID(t *testing.T) {

	tests := []struct {
		name    string
		id      int64
		wantErr error
	}{
		{name: "one", id: 1},
		{name: "large", id: 1 << 62},
		{name: "zero", id: 0, wantErr: customerrors.ErrIDNegative},
		{name: "negative", id: -5, wantErr: customerrors.ErrIDNegative},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			v := testValidator()

			if err := v.ValidateUserID(tt.id); !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateUserID(%d) error = %v, want %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestNewUserValidatorDefaultSetup(t *testing.T) {

	got := NewUserValidatorDefaultSetup()

	if want := NewDefaultPasswordRules(); got.passwordrules != want {
		t.Errorf("password rules = %+v, want %+v", got.passwordrules, want)
	}

	if want := NewDefaultUsernameRules(); got.usernamerules != want {
		t.Errorf("username rules = %+v, want %+v", got.usernamerules, want)
	}
}

func TestNewDefaultPasswordRules(t *testing.T) {

	want := PasswordRules{
		MinLength:      setup.PWD_MinLength,
		MaxLength:      setup.PWD_MaxLength,
		MinUppercase:   setup.PWD_MinUppercase,
		MinLowercase:   setup.PWD_MinLowercase,
		MinDigits:      setup.PWD_MinDigits,
		MinSymbols:     setup.PWD_MinSymbols,
		ForbiddenChars: setup.PWD_ForbiddenChars,
	}

	if got := NewDefaultPasswordRules(); got != want {
		t.Errorf("NewDefaultPasswordRules() = %+v, want %+v", got, want)
	}
}

func TestNewDefaultUsernameRules(t *testing.T) {

	want := UsernameRules{
		MinLength:         setup.UName_MinLength,
		MaxLength:         setup.UName_MaxLength,
		AllowSpecialChars: setup.UName_AllowSpecialChars,
		ForbiddenChars:    setup.UName_ForbiddenChars,
	}

	if got := NewDefaultUsernameRules(); got != want {
		t.Errorf("NewDefaultUsernameRules() = %+v, want %+v", got, want)
	}
}
