package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/pranavagiligar/the_switch/internal/utils"
)

var DB *sql.DB

// InitializeDB initializes the SQLite database, creates tables, and sets up the default admin user.
func InitializeDB(dbPath, adminPassword string) error {
	var err error

	// Open the database for persistence.
	DB, err = sql.Open("sqlite3", dbPath+"?_foreign_keys=on&busy_timeout=10000&_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("error opening persistent database at %s: %w", dbPath, err)
	}

	// Create Users table (no change)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			passwordHash TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}

	// Update Jobs table schema (Feature 3)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			cronExpression TEXT NOT NULL,
			scriptContent TEXT NOT NULL,
			skipCount INTEGER DEFAULT 0,
			createdAt INTEGER NOT NULL,
			updatedAt INTEGER NOT NULL,
			envVars TEXT DEFAULT '{}',
			notifyBeforeSeconds INTEGER DEFAULT 0,
			notifyOnExecution BOOLEAN DEFAULT 0
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating jobs table: %w", err)
	}

	// Run a lightweight migration for existing DBs: ensure notifyBeforeSeconds column exists
	// SQLite supports ALTER TABLE ADD COLUMN; check pragma table_info
	rows, merr := DB.Query("PRAGMA table_info(jobs);")
	if merr == nil {
		defer rows.Close()
		foundNotify := false
		foundUpdatedAt := false
		for rows.Next() {
			var cid int
			var name string
			var ctype string
			var notnull int
			var dfltValue sql.NullString
			var pk int
			if scanErr := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); scanErr == nil {
				if name == "notifyBeforeSeconds" {
					foundNotify = true
				}
				if name == "updatedAt" {
					foundUpdatedAt = true
				}
			}
		}
		if !foundNotify {
			_, aerr := DB.Exec("ALTER TABLE jobs ADD COLUMN notifyBeforeSeconds INTEGER DEFAULT 0;")
			if aerr != nil {
				log.Printf("[MIGRATION] Failed to add notifyBeforeSeconds column: %v", aerr)
			} else {
				log.Printf("[MIGRATION] notifyBeforeSeconds column added to jobs table")
			}
		}
		if !foundUpdatedAt {
			_, aerr := DB.Exec("ALTER TABLE jobs ADD COLUMN updatedAt INTEGER DEFAULT 0;")
			if aerr != nil {
				log.Printf("[MIGRATION] Failed to add updatedAt column: %v", aerr)
			} else {
				log.Printf("[MIGRATION] updatedAt column added to jobs table")
			}
		}

		// Check for notifyOnExecution column
		foundNotifyExec := false
		rows, merr = DB.Query("PRAGMA table_info(jobs);") // Re-query to be safe
		if merr == nil {
			defer rows.Close()
			for rows.Next() {
				var cid int
				var name string
				var ctype string
				var notnull int
				var dfltValue sql.NullString
				var pk int
				if scanErr := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); scanErr == nil {
					if name == "notifyOnExecution" {
						foundNotifyExec = true
					}
				}
			}
		}
		if !foundNotifyExec {
			_, aerr := DB.Exec("ALTER TABLE jobs ADD COLUMN notifyOnExecution BOOLEAN DEFAULT 0;")
			if aerr != nil {
				log.Printf("[MIGRATION] Failed to add notifyOnExecution column: %v", aerr)
			} else {
				log.Printf("[MIGRATION] notifyOnExecution column added to jobs table")
			}
		}
	} else {
		log.Printf("[MIGRATION] Could not introspect jobs table: %v", merr)
	}

	// NEW: Create Job Executions table (Feature 1)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS job_executions (
			id INTEGER PRIMARY KEY,
			jobId INTEGER NOT NULL,
			status TEXT NOT NULL, 
			startTime INTEGER NOT NULL,
			duration INTEGER NOT NULL, -- milliseconds
			exitCode INTEGER NOT NULL,
			output TEXT,
			FOREIGN KEY(jobId) REFERENCES jobs(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating job_executions table: %w", err)
	}

	// Set up admin user
	adminUsername := "admin"
	if adminPassword == "" {
		adminPassword = "password" // Default password
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing password: %w", err)
	}

	// Insert or replace admin user
	_, err = DB.Exec("INSERT OR REPLACE INTO users (id, username, passwordHash) VALUES (1, ?, ?)", adminUsername, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("error inserting admin user: %w", err)
	}

	// Check if a mock job exists, if not, create one
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM jobs").Scan(&count)
	if err != nil {
		log.Printf("Error counting jobs: %v", err)
	}
	if count == 0 {
		log.Println("Inserting mock job...")
		mockCron := "0 0 * * *" // Midnight every day
		mockScript := `
# Simple job that logs date and time to stdout
echo "Job executed successfully at $(date)"
# Example of using an environment variable (API_KEY)
echo "API Key check: $API_KEY"
`
		// Mock EnvVars (Feature 3)
		mockEnvVars := map[string]string{"API_KEY": "test_api_key_123", "LOG_LEVEL": "INFO"}
		envVarsJSON, _ := utils.MapToJSON(mockEnvVars)

		now := time.Now().UnixNano() / int64(time.Millisecond)
		_, err = DB.Exec(`
			INSERT INTO jobs (title, description, cronExpression, scriptContent, createdAt, updatedAt, envVars) 
			VALUES (?, ?, ?, ?, ?, ?, ?);
		`, "Daily Health Check", "Runs a simple script every night to verify system health and use an EnvVar.", mockCron, mockScript, now, now, envVarsJSON)
		if err != nil {
			log.Printf("Error inserting mock job: %v", err)
		}
	}

	log.Printf("Database initialized successfully. Using persistent file: %s", dbPath)
	return nil
}

func Close() {
	if DB != nil {
		DB.Close()
	}
}
