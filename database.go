package main

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type Threat struct {
	ID         int       `db:"id" json:"id"`
	FeedSource string    `db:"feed_source" json:"feed_source"`
	ThreatType string    `db:"threat_type" json:"threat_type"`
	Indicator  string    `db:"indicator" json:"indicator"`
	RawData    string    `db:"raw_data" json:"raw_data"`
	SeenAt     time.Time `db:"seen_at" json:"seen_at"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

func initDB() *sqlx.DB {
	db, err := sqlx.Connect("sqlite", "threat_dashboard.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	db.SetMaxOpenConns(1)                // SQLite doesn't handle multiple writers well, so we limit to 1 connection
	db.Exec("PRAGMA journal_mode=WAL;")  // Enable Write-Ahead Logging for better concurrency
	db.Exec("PRAGMA busy_timeout=5000;") // Wait up to 5 seconds if the database is locked
	schema := `
	CREATE TABLE IF NOT EXISTS threats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		feed_source TEXT NOT NULL,
		threat_type TEXT NOT NULL DEFAULT 'unknown',
		indicator TEXT NOT NULL,
		raw_data TEXT,
		seen_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(feed_source, indicator) --prevent duplicate entries from the same feed
	);
	CREATE INDEX IF NOT EXISTS idx_feed_source ON threats(feed_source);
	CREATE INDEX IF NOT EXISTS idx_threats_seen_at ON threats(seen_at DESC);

	CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_source TEXT     NOT NULL,
    threat_type TEXT     NOT NULL DEFAULT 'unknown',
    indicator   TEXT     NOT NULL,
    raw_data    TEXT,
    seen_at     DATETIME NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(feed_source, indicator)
);
CREATE INDEX IF NOT EXISTS idx_feed ON threats(feed_source);
CREATE INDEX IF NOT EXISTS idx_seen ON threats(seen_at DESC);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip         TEXT PRIMARY KEY,
    lat        REAL,
    lng        REAL,
    country    TEXT,
    city       TEXT,
    looked_up_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

	
`

	// One-time cleanup on every startup: remove any threats that are
	// older than our staleness threshold, so leftover old data from
	// previous runs doesn't linger in the dashboard.
	_, err = db.Exec(`
    DELETE FROM threats
    WHERE feed_source = 'FeodoTracker'
    AND seen_at < datetime('now', '-60 days')
`)
	if err != nil {
		log.Printf("Cleanup warning: %v\n", err)
	}
	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal("Failed to create database schema:", err)
	}

	log.Println("Database initialized successfully.")
	return db
}

// Returns (wasInserted, error). wasInserted is false if this exact
// threat already existed and SQLite silently ignored the insert.
func insertThreat(db *sqlx.DB, threat Threat) (bool, error) {
	query := `
	INSERT OR IGNORE INTO threats (feed_source, threat_type, indicator, raw_data, seen_at)
	VALUES (:feed_source, :threat_type, :indicator, :raw_data, :seen_at)
	`
	result, err := db.NamedExec(query, threat)
	if err != nil {
		return false, err
	}

	// RowsAffected() tells us how many rows the database actually changed.
	// With INSERT OR IGNORE: 1 = genuinely new row, 0 = duplicate, silently skipped
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}
