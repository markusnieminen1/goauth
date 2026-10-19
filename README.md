# goauth

Not ready yet. 

Cookie based authentication for Go services: register, login, refresh, logout. Every part sits behind an interface and has a default, so it works with zero config and any part can be swapped.

## Quick start

```sh
go get github.com/markusnieminen1/goauth
```

```go
app, err := goauth.NewAuthApp(goauth.Config{}) // bcrypt, JWT, sqlite (./auth.db), UUID refresh tokens
if err != nil {
	log.Fatal(err)
}
defer app.Close()
if err = app.ConfigTest(ctx); err != nil { // optional: self-check on a private temporary DB
	log.Fatal(err)
}

user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "a@b.fi", Username: "alice", Password: "Sup3r-secret!"})
cookies, err := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "Sup3r-secret!"}) // set these on the response
userID, err := app.Authenticator.Authenticate(ctx, cookies)      // validate the access token
cookies, err = app.AuthenticationService.Refresh(ctx, cookies)   // new tokens, the old refresh token is revoked
expired, err := app.AuthenticationService.Logout(ctx, cookies)   // revoke, then set these to overwrite the client's tokens
```

```go
// Get the user id from request (int64)
userId := goauth.handlers.UserID(r)
```

## Structure 
```
.
├── components
│   ├── caching (NOT REALLY IMPLEMENTED JUST YET)
│   │   ├── dummy
│   │   ├── go_native
│   │   └── redis
│   ├── hashing
│   │   ├── argon (NOT IMPLEMENTED JUST YET)
│   │   ├── bcrypt
│   │   └── dummy
│   └── token
│       ├── dummy
│       ├── jwt (Access tokens)
│       └── uuid (v4, Refresh tokens)
├── docs
│   └── creating_custom_package (Drafting idea)
├── domain
│   ├── customerrors (Errors)
│   └── sharedmodels (Data models)
├── handlers (Middleware, Endpoints not in use)
├── internal 
│   └── validating (Email, username, password, rules)
├── service (Service level interfaces and implementations for Accounts, Sessions, Tokens)
├── setup
└── store
    ├── database (Database setup)
    │   ├── dummydbfortest
    │   └── sqlite
    │       ├── schema
    │       └── sqlitemattn
    ├── session (Sessions in DB)
    │   ├── redis
    │   └── sqlite
    └── user (Users in DB)
        ├── dummy
        ├── postgres
        └── sqlite

```

The app does the work, the HTTP layer is yours. Ready made handlers and middleware (`app.Middleware`, package `handlers`) exist but are optional.

Replace a default by setting its `Config` field: `Hasher`, `Access`, `Refresh`, `Users`, `Sessions`, `Cache` (none by default), or `DB` to use your own sqlite database.

## Components

```mermaid
classDiagram
    direction LR

    class App {
        AccountService
        AuthenticationService
        Authenticator
        Middleware
        -cfg Config
        -ownedDB *sql.DB
        Close() error
    }

    class Config {
        Hasher = bcrypt
        Access = JWT EdDSA
        Refresh = UUID + SHA-256
        Users = sqlite
        Sessions = sqlite
        Cache = none
        DB *sql.DB
    }

    class Middleware {
        Ratelimiter
        ExtractCookies
        ValidateToken
        RequireAuthRoute
        OptionalAuthRoute
    }

    class AccountService {
        <<interface>>
        Register()
        GetByID()
        UpdateEmail()
        UpdateUsername()
        ChangePassword()
        Delete()
    }

    class AuthenticationService {
        <<interface>>
        Login()
        Refresh()
        Logout()
        LogoutAll()
    }

    class Authenticator {
        <<interface>>
        Authenticate()
        Refresh()
    }

    App *-- AccountService
    App *-- AuthenticationService
    App *-- Authenticator
    App *-- Middleware
    App o-- Config : cfg
    Middleware ..> Authenticator : validates tokens with
    AccountService ..> Config : Hasher, Users, Sessions
    AuthenticationService ..> Config : Hasher, Users, Sessions, Access, Refresh, Cache
```
