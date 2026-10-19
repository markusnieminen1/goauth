package setup

var (
	// --------------
	// Headers
	// --------------

	ACCESS_TOKEN_NAME         = "Access"
	REFRESH_TOKEN_NAME        = "Refresh"
	ACCESS_TOKEN_EXPIRY_MIN   = 5
	REFRESH_TOKEN_EXPIRY_DAYS = 14

	// --------------
	// Cookies
	// --------------

	COOKIE_PATH     = "/" // "/" so that the cookies get sent to every path
	COOKIE_DOMAIN   = ""
	COOKIE_HTTPONLY = true
	COOKIE_SECURE   = false
	COOKIE_SAMESITE = "Strict"

	// --------------
	// Tokens
	// --------------

	JWT_KeyFile = "jwt_ed25519.pem" // Ed25519 private key, created if missing

	// --------------
	// Hashing
	// --------------

	BCRYPT_Cost = 12 // work factor, 4..31

	// --------------
	// Password
	// --------------

	PWD_MinLength    = 8
	PWD_MaxLength    = 72 // bcrypt ignores everything past 72 bytes
	PWD_MinUppercase = 1
	PWD_MinLowercase = 1
	PWD_MinDigits    = 1
	PWD_MinSymbols   = 1

	PWD_ForbiddenChars = ""

	// --------------
	// Username
	// --------------

	UName_MinLength         = 3
	UName_MaxLength         = 30
	UName_AllowSpecialChars = false

	UName_ForbiddenChars = " "

	// --------------
	// Email
	// --------------

	Email_MaxLength = 254

	// --------------
	// Middleware
	// --------------

	RequestPerInterval                 = 8    // General ratelimiter
	RequesIntervalMillis               = 1000 // General ratelimiter
	ProtectedRouteRequestPerInterval   = 5    // ratelimiter for protected endpoints, makes it possible to have lower threshold for endpoinds that requires processing
	ProtectedRouteRequesIntervalMillis = 1000 // ratelimiter for protected endpoints, makes it possible to have lower threshold for endpoinds that requires processing

	// --------------
	// Database
	// --------------

	AuthDbDefaultPath = "./auth.db"
	DB_ForeignKeys    = true
	DB_BusyTimeoutMs  = 5000
)
