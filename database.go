package main

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

)

type Threat struct{
	ID          int       `db:"id"`
	FeedSource	string    `db:"feed_source"`
	ThreatType	string    `db:"threat_type"`
	Indicator	string    `db:"indicator"`
	RawData     string    `db:"raw_data"`
	SeenAt	 time.Time `db:"seen_at"`
	CreatedAt   time.Time `db:"created_at"`
}
func initDB() *sqlx.DB {
	db, err := sqlx.Connect("sqlite", "threat_dashboard.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	db.SetMaxOpenConns(1) // SQLite doesn't handle multiple writers well, so we limit to 1 connection
	db.Exec("PRAGMA journal_mode=WAL;") // Enable Write-Ahead Logging for better concurrency
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
`
	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal("Failed to create database schema:", err)
	}

	log.Println("Database initialized successfully.")
	return db
}

func insertThreat(db *sqlx.DB, threat Threat) error {
	query := `
	INSERT OR IGNORE INTO threats (feed_source, threat_type, indicator, raw_data, seen_at)
	VALUES (:feed_source, :threat_type, :indicator, :raw_data, :seen_at)
	`
	_, err := db.NamedExec(query, threat)
	return err
}