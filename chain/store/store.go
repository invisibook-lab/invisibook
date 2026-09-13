// Package store owns the chain's single SQLite database.
//
// Orders and cash are both consensus state mutated by the same block, so they
// live in one database behind one handle. Splitting them across two files left
// a settlement — which marks orders Done in one and spends cash in the other —
// with no way to be atomic, and no way to be undone together either.
package store

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open opens the chain database at `dsn` and returns the handle every tripod
// writes through. Each tripod migrates its own tables.
func Open(dsn string, logLevel logger.LogLevel) (*gorm.DB, error) {
	gormLogger := logger.New(
		log.New(os.Stdout, "\n", log.LstdFlags),
		logger.Config{
			SlowThreshold: 200 * time.Millisecond,
			LogLevel:      logLevel,
		},
	)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormLogger})
	if err != nil {
		return nil, fmt.Errorf("opening chain database %s: %w", dsn, err)
	}
	return db, nil
}

// ParseGormLogLevel converts a string log level to gorm's.
// Accepted values: "silent", "error", "warn", "info". Defaults to Warn.
func ParseGormLogLevel(level string) logger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent":
		return logger.Silent
	case "error":
		return logger.Error
	case "info":
		return logger.Info
	default:
		return logger.Warn
	}
}
