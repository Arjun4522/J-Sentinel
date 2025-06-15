// db_setup.go
package main

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbFileName = "data.db"
)

// DB represents the database connection
type DB struct {
	conn *sql.DB
}

// NewDB creates a new database connection and initializes the schema
func NewDB(dataDir string) (*DB, error) {
	dbPath := filepath.Join(dataDir, dbFileName)
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// initSchema creates the database tables if they don't exist
func (db *DB) initSchema() error {
	// Create scans table with updated schema
	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS scans (
		scanId TEXT PRIMARY KEY,
		source_directory TEXT NOT NULL,
		filesProcessed INTEGER NOT NULL,
		vulnerabilitiesFound INTEGER NOT NULL,
		duration INTEGER NOT NULL,
		timestamp TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create scans table: %w", err)
	}

	// Create directory_history table
	_, err = db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS directory_history (
		directory TEXT NOT NULL,
		first_scan TEXT NOT NULL,
		last_scan TEXT NOT NULL,
		scan_count INTEGER NOT NULL DEFAULT 1,
		PRIMARY KEY (directory)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create directory_history table: %w", err)
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}