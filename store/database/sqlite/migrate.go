package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/markusnieminen1/basic-auth/store/database"
)

//go:embed schema/tables.sql
var tablesSQL string

//go:embed schema/indexes.sql
var indexesSQL string

type column struct {
	name       string
	definition string
}

type tableSpec struct {
	name    string
	key     string
	columns []column
}

var tables = []tableSpec{
	{name: "users", key: "id", columns: []column{
		{"username", "TEXT NOT NULL DEFAULT ''"},
		{"email", "TEXT NOT NULL DEFAULT ''"},
		{"pwd_hash", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "user_sessions", key: "session_id", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"refresh_token", "TEXT NOT NULL DEFAULT ''"},
		{"valid_until", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "path_permissions", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"path", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "ops_permissions", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"operation", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "events", key: "event_id", columns: []column{
		{"ip", "TEXT NOT NULL DEFAULT ''"},
		{"event", "TEXT NOT NULL DEFAULT ''"},
		{"user_id", "INTEGER"},
	}},
	{name: "audit", key: "audit_id", columns: []column{
		{"ip", "TEXT NOT NULL DEFAULT ''"},
		{"event", "TEXT NOT NULL DEFAULT ''"},
		{"user_id", "INTEGER"},
	}},
}

func Migrate(ctx context.Context, db *sql.DB) error {

	if db == nil {
		return database.ErrOpenDbFail
	}

	tx, err := db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}

	defer tx.Rollback()

	existing := make(map[string]map[string]bool, len(tables))

	for _, spec := range tables {
		cols, err := columnsOf(ctx, tx, spec.name)
		if err != nil {
			return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
		}

		existing[spec.name] = cols
	}

	if _, err = tx.ExecContext(ctx, tablesSQL); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}

	for _, spec := range tables {
		if err = addMissingColumns(ctx, tx, spec, existing[spec.name]); err != nil {
			return err
		}
	}

	if _, err = tx.ExecContext(ctx, indexesSQL); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}

	return nil
}

func addMissingColumns(ctx context.Context, tx *sql.Tx, spec tableSpec, have map[string]bool) error {

	if len(have) == 0 {
		return nil
	}

	if spec.key != "" && !have[spec.key] {
		return fmt.Errorf("%w: table %s has no %s column", database.ErrIncompatibleSchema, spec.name, spec.key)
	}

	for _, col := range spec.columns {
		if have[col.name] {
			continue
		}

		// Names come from the constant table above, never from input.
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", spec.name, col.name, col.definition)
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w: add %s.%s: %v", database.ErrInitDbFail, spec.name, col.name, err)
		}
	}

	return nil
}

func columnsOf(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {

	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)

	if err != nil {
		return nil, err

	}

	defer rows.Close()

	cols := make(map[string]bool)

	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}

		cols[name] = true
	}

	return cols, rows.Err()
}
