// Package sqlitemattn mattn/go-sqlite3 driver
package sqlitemattn

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"

	"github.com/markusnieminen1/goauth/setup"
	"github.com/markusnieminen1/goauth/store/database"
	"github.com/markusnieminen1/goauth/store/database/sqlite"
	_ "github.com/mattn/go-sqlite3"
)

func Open(ctx context.Context, path string) (*sql.DB, error) {

	query := url.Values{}
	if setup.DB_ForeignKeys {
		query.Set("_foreign_keys", "on")
	}

	query.Set("_busy_timeout", strconv.Itoa(setup.DB_BusyTimeoutMs))

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?%s", path, query.Encode()))

	if err != nil {
		return nil, fmt.Errorf("%w: %v", database.ErrOpenDbFail, err)
	}

	if err = db.PingContext(ctx); err != nil {
		db.Close()

		return nil, fmt.Errorf("%w: %v", database.ErrOpenDbFail, err)
	}

	if err = sqlite.Migrate(ctx, db); err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
}
