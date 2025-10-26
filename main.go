package main

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
)

//go:embed index.html
var indexHTML []byte

var version = "dev"
var commit = "none"
var buildTime = "unknown"

// Job defines the structure for a scheduled job.
type Job struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	CronExpression string `json:"cronExpression"`
	ScriptContent  string `json:"scriptContent"`
	SkipCount      int    `json:"skipCount"`
	CreatedAt      int64  `json:"createdAt"`
	NextRunAt      int64  `json:"nextRunAt"` // Unix milliseconds timestamp for the next run
	// NEW: For Job-Specific Environment Variables (Feature 3)
	EnvVars map[string]string `json:"envVars,omitempty"` // Stored as JSON string in DB
}

// NEW: JobExecution defines the structure for an execution log entry (Feature 1)
type JobExecution struct {
	ID        string `json:"id"`
	JobID     string `json:"jobId"`     // Used to link to the Job
	Status    string `json:"status"`    // "Success" or "Failure"
	StartTime int64  `json:"startTime"` // Unix milliseconds
	Duration  int64  `json:"duration"`  // Duration in milliseconds
	ExitCode  int    `json:"exitCode"`
	Output    string `json:"output"` // Combined STDOUT and STDERR
}

// UserLogin defines the structure for incoming login data.
type UserLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims defines the structure for the JWT payload.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	db *sql.DB
	// Secret key for signing the JWT.
	jwtKey []byte

	// Global cron instance, mutex, and the parser instance
	jobCron   *cron.Cron
	cronMutex sync.Mutex
	jobParser cron.Parser
)

// --- Utility Functions ---

// enableCORS adds CORS headers to allow frontend access
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal Server Error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

// getTokenFromHeader extracts the JWT from the Authorization header
func getTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header required")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization format")
	}
	return parts[1], nil
}

// authMiddleware checks for a valid JWT before proceeding to the handler
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := getTokenFromHeader(r)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized access: " + err.Error()})
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			status := http.StatusUnauthorized
			errorMsg := "Invalid or expired token"
			if err != nil && strings.Contains(err.Error(), "token is expired") {
				errorMsg = "Token expired"
			}
			respondJSON(w, status, map[string]string{"error": errorMsg})
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	}
}

// serves the index.html file
func serveIndexFile(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// Converts a Go map to a JSON string for DB storage (Feature 3)
func mapToJSON(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// Converts a JSON string from DB to a Go map (Feature 3)
func jsonToMap(s string) (map[string]string, error) {
	if s == "" || s == "null" || s == "{}" {
		return make(map[string]string), nil
	}
	var m map[string]string
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
		log.Printf("[WARNING] Failed to parse envVars JSON: %v. JSON string: %s", err, s)
		// Return empty map on error to prevent execution failure due to bad DB data
		return make(map[string]string), nil
	}
	return m, nil
}

// Helper to convert "job-ID" to int
func getNumericJobID(jobID string) (int, error) {
	var numericID int
	if _, err := fmt.Sscanf(jobID, "job-%d", &numericID); err != nil {
		return 0, fmt.Errorf("invalid job ID format: %s", jobID)
	}
	return numericID, nil
}

// --- Scheduler and Execution Logic ---

// NEW: Separates execution logic for re-use by scheduler and manual run handler (Feature 1 & 3)
func executeAndLogJob(job Job) {
	// 1. Prepare environment variables (Feature 3)
	// Start with the system's current environment variables
	env := os.Environ()
	if job.EnvVars != nil {
		for key, val := range job.EnvVars {
			// Prepend key=value to the command's environment, overriding system variables if needed
			env = append(env, fmt.Sprintf("%s=%s", key, val))
		}
	}

	// 2. Setup execution (Feature 1)
	startTime := time.Now()
	numericID, err := getNumericJobID(job.ID)
	if err != nil {
		log.Printf("[ERROR] Invalid job ID format for execution: %v", err)
		return
	}

	// 3. Execute the script
	// Run the script content via /bin/bash -c for robust shell execution
	cmd := exec.Command("/bin/bash", "-c", job.ScriptContent)
	cmd.Env = env // Set environment variables (Feature 3)
	output, cmdErr := cmd.CombinedOutput()

	// 4. Log results (Feature 1)
	duration := time.Since(startTime).Milliseconds()
	status := "Success"
	exitCode := 0

	if cmdErr != nil {
		status = "Failure"
		// Check if the error is an ExitError to get the non-zero exit code
		if exitErr, ok := cmdErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1 // Non-ExitError failure (e.g., command not found)
			// Add non-ExitError to output for debugging
			output = append(output, []byte("\n[Go Execution Error] "+cmdErr.Error())...)
		}
		log.Printf("[EXECUTION FAILED] Job %s failed: %v\nExit Code: %d\nDuration: %dms", job.Title, cmdErr, exitCode, duration)
	} else {
		log.Printf("[EXECUTION SUCCESS] Job %s finished.\nExit Code: %d\nDuration: %dms", job.Title, exitCode, duration)
	}

	// 5. Store log to database (Feature 1)
	_, dbErr := db.Exec(`
		INSERT INTO job_executions (jobId, status, startTime, duration, exitCode, output)
		VALUES (?, ?, ?, ?, ?, ?);
	`, numericID, status, startTime.UnixNano()/int64(time.Millisecond), duration, exitCode, string(output))

	if dbErr != nil {
		log.Printf("[DB ERROR] Failed to store execution log for job %s: %v", job.ID, dbErr)
	}
}

// runJob executes the script content for a given job (called by cron).
func runJob(job Job) func() {
	return func() {
		log.Printf("[SCHEDULER] Job %s (ID: %s) triggered with cron: %s", job.Title, job.ID, job.CronExpression)

		// Check and handle skip count
		var currentSkipCount int
		numericID, err := getNumericJobID(job.ID)
		if err != nil {
			log.Printf("[ERROR] Failed to parse job ID in runJob: %v", err)
			return
		}

		err = db.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", numericID).Scan(&currentSkipCount)
		if err != nil {
			log.Printf("[ERROR] Failed to read skipCount for job %s: %v", job.ID, err)
			return
		}

		if currentSkipCount > 0 {
			// Decrement skip count and skip execution
			_, err = db.Exec("UPDATE jobs SET skipCount = ? WHERE id = ?", currentSkipCount-1, numericID)
			if err != nil {
				log.Printf("[ERROR] Failed to decrement skipCount for job %s: %v", job.ID, err)
			}
			log.Printf("[SKIP] Job %s skipped. Remaining skips: %d", job.Title, currentSkipCount-1)
			return
		}

		// Execute and log the job using the shared function
		executeAndLogJob(job)
	}
}

// startScheduler fetches all jobs and sets up the cron schedule.
func startScheduler() {
	cronMutex.Lock()
	defer cronMutex.Unlock()

	// 1. Stop the current scheduler if it's running
	if jobCron != nil {
		log.Println("[SCHEDULER] Stopping existing cron scheduler...")
		ctx := jobCron.Stop()
		<-ctx.Done() // Wait for the stop signal
	}

	// 2. Initialize a new scheduler
	newParser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	jobCron = cron.New(cron.WithParser(newParser))
	jobParser = newParser

	log.Println("[SCHEDULER] Fetching all jobs to schedule...")

	// 3. Fetch all jobs from the database (including envVars)
	rows, err := db.Query(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, envVars
		FROM jobs;
	`)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch jobs for scheduler: %v", err)
		return
	}
	defer rows.Close()

	// 4. Add each job to the scheduler
	jobsScheduled := 0
	for rows.Next() {
		var job Job
		var id int
		var envVarsJSON string // Scan EnvVars JSON string (Feature 3)

		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &envVarsJSON)
		if err != nil {
			log.Printf("[ERROR] Error scanning job row for scheduling: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

		// Deserialize envVars (Feature 3)
		job.EnvVars, _ = jsonToMap(envVarsJSON)

		// Add the job to cron
		_, err = jobCron.AddFunc(job.CronExpression, runJob(job))
		if err != nil {
			log.Printf("[ERROR] Failed to schedule job %s (%s): %v", job.Title, job.CronExpression, err)
			continue
		}
		jobsScheduled++
	}

	// 5. Start the new scheduler in a background goroutine
	jobCron.Start()
	log.Printf("[SCHEDULER] Scheduler successfully restarted. %d jobs scheduled.", jobsScheduled)
}

// --- Database Initialization and Setup ---

// initializeDB initializes the SQLite database, creates tables, and sets up the default admin user.
func initializeDB(dbPath, adminPassword string) error {
	var err error

	// Open the database for persistence.
	db, err = sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return fmt.Errorf("error opening persistent database at %s: %w", dbPath, err)
	}

	// Create Users table (no change)
	_, err = db.Exec(`
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
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			cronExpression TEXT NOT NULL,
			scriptContent TEXT NOT NULL,
			skipCount INTEGER DEFAULT 0,
			createdAt INTEGER NOT NULL,
			-- NEW: Environment variables stored as JSON string
			envVars TEXT DEFAULT '{}' 
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating jobs table: %w", err)
	}

	// NEW: Create Job Executions table (Feature 1)
	_, err = db.Exec(`
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
	_, err = db.Exec("INSERT OR REPLACE INTO users (id, username, passwordHash) VALUES (1, ?, ?)", adminUsername, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("error inserting admin user: %w", err)
	}

	// Check if a mock job exists, if not, create one
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM jobs").Scan(&count)
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
		envVarsJSON, _ := mapToJSON(mockEnvVars)

		now := time.Now().UnixNano() / int64(time.Millisecond)
		_, err = db.Exec(`
			INSERT INTO jobs (title, description, cronExpression, scriptContent, createdAt, envVars) 
			VALUES (?, ?, ?, ?, ?, ?);
		`, "Daily Health Check", "Runs a simple script every night to verify system health and use an EnvVar.", mockCron, mockScript, now, envVarsJSON)
		if err != nil {
			log.Printf("Error inserting mock job: %v", err)
		}
	}

	log.Printf("Database initialized successfully. Using persistent file: %s", dbPath)
	return nil
}

// --- Authentication Handlers ---

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var userLogin UserLogin
	if err := json.NewDecoder(r.Body).Decode(&userLogin); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	var passwordHash string
	var userID int
	err := db.QueryRow("SELECT id, passwordHash FROM users WHERE username = ?", userLogin.Username).Scan(&userID, &passwordHash)

	if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(userLogin.Password)) != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
		return
	}

	// Create the JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: fmt.Sprintf("%d", userID),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not create token"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

// --- Job Management Handlers (Updated for Features 1, 2, 3) ---

// getJobsHandler is updated to fetch envVars and calculate NextRunAt
func getJobsHandler(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, envVars
		FROM jobs ORDER BY createdAt DESC;
	`)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	cronMutex.Lock()
	parser := jobParser
	cronMutex.Unlock()
	jobList := []Job{}
	now := time.Now()

	for rows.Next() {
		var job Job
		var id int
		var envVarsJSON string // Read envVars (Feature 3)
		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &envVarsJSON)
		if err != nil {
			log.Printf("[ERROR] Error scanning job row for API: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

		// Deserialize envVars (Feature 3)
		job.EnvVars, _ = jsonToMap(envVarsJSON)

		// Calculate Next Run At
		schedule, parseErr := parser.Parse(job.CronExpression)
		if parseErr != nil {
			log.Printf("[ERROR] Failed to parse cron expression '%s' for job %s: %v", job.CronExpression, job.ID, parseErr)
			job.NextRunAt = 0 // Indicate failure/unknown
		} else {
			// Start from current time
			nextTime := schedule.Next(now)

			// Apply SkipCount: iterate schedule.Next() SkipCount times to find the effective run time
			for i := 0; i < job.SkipCount; i++ {
				nextTime = schedule.Next(nextTime)
			}

			// Convert time.Time to Unix milliseconds for the frontend
			job.NextRunAt = nextTime.UnixNano() / int64(time.Millisecond)
		}

		jobList = append(jobList, job)
	}

	respondJSON(w, http.StatusOK, jobList)
}

// createJobHandler is updated to handle envVars
func createJobHandler(w http.ResponseWriter, r *http.Request) {
	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	// 1. Serialize envVars map to JSON string (Feature 3)
	envVarsJSON, err := mapToJSON(job.EnvVars)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid environment variables format"})
		return
	}

	// 2. Validate CRON
	cronMutex.Lock()
	_, err = jobParser.Parse(job.CronExpression)
	cronMutex.Unlock()
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CRON expression: " + err.Error()})
		return
	}

	// 3. Insert into DB (updated to include envVars)
	now := time.Now().UnixNano() / int64(time.Millisecond)
	res, err := db.Exec(`
		INSERT INTO jobs (title, description, cronExpression, scriptContent, skipCount, createdAt, envVars) 
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, 0, now, envVarsJSON) // Added envVars

	if err != nil {
		log.Printf("[DB ERROR] Failed to create job: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create job in database"})
		return
	}

	// Get the newly created ID
	lastInsertID, _ := res.LastInsertId()
	job.ID = fmt.Sprintf("job-%d", lastInsertID)

	// Restart scheduler to include the new job
	go startScheduler()

	respondJSON(w, http.StatusCreated, job)
}

// updateJobHandler is updated to handle envVars
func updateJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		http.NotFound(w, r)
		return
	}
	jobIDStr := pathParts[3]
	numericID, err := getNumericJobID(jobIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	// 1. Serialize envVars map to JSON string (Feature 3)
	envVarsJSON, err := mapToJSON(job.EnvVars)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid environment variables format"})
		return
	}

	// 2. Validate CRON
	cronMutex.Lock()
	_, err = jobParser.Parse(job.CronExpression)
	cronMutex.Unlock()
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CRON expression: " + err.Error()})
		return
	}

	// 3. Update DB (updated to include envVars)
	res, err := db.Exec(`
		UPDATE jobs SET title = ?, description = ?, cronExpression = ?, scriptContent = ?, skipCount = ?, envVars = ?
		WHERE id = ?;
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, job.SkipCount, envVarsJSON, numericID) // Added envVars

	if err != nil {
		log.Printf("[DB ERROR] Failed to update job %s: %v", jobIDStr, err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update job in database"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}

	// Restart scheduler to update the job's schedule/logic/envvars
	go startScheduler()

	respondJSON(w, http.StatusOK, map[string]string{"message": "Job updated successfully"})
}

func deleteJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		http.NotFound(w, r)
		return
	}
	jobIDStr := pathParts[3]
	numericID, err := getNumericJobID(jobIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	// DELETE is set to cascade, so job_executions are also deleted.
	res, err := db.Exec("DELETE FROM jobs WHERE id = ?", numericID)
	if err != nil {
		log.Printf("[DB ERROR] Failed to delete job %s: %v", jobIDStr, err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete job"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}

	// Restart scheduler to remove the deleted job's entry
	go startScheduler()

	w.WriteHeader(http.StatusNoContent)
}

func skipJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := getNumericJobID(jobIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	// Atomically increment skip count
	_, err = db.Exec("UPDATE jobs SET skipCount = skipCount + 1 WHERE id = ?", numericID)
	if err != nil {
		log.Printf("[DB ERROR] Failed to skip job %s: %v", jobIDStr, err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to skip job"})
		return
	}

	// Fetch the new skip count to return it
	var newSkipCount int
	err = db.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", numericID).Scan(&newSkipCount)
	if err != nil {
		log.Printf("[DB ERROR] Failed to fetch new skip count for job %s: %v", jobIDStr, err)
		respondJSON(w, http.StatusOK, map[string]interface{}{"message": "Job skipped, but failed to fetch new count", "skipCount": -1})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"message": "Job skipped successfully", "skipCount": newSkipCount})
}

// NEW: Handlers for Manual Execution and History (Feature 2 & 1)

// runJobManuallyHandler handles POST /api/jobs/{id}/run (Feature 2)
func runJobManuallyHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := getNumericJobID(jobIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	// 1. Fetch job details
	var job Job
	var envVarsJSON string
	err = db.QueryRow(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, envVars
		FROM jobs WHERE id = ?
	`, numericID).Scan(&numericID, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &envVarsJSON)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}
	if err != nil {
		log.Printf("[DB ERROR] Failed to fetch job %s for manual run: %v", jobIDStr, err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch job data"})
		return
	}

	job.ID = jobIDStr
	job.EnvVars, _ = jsonToMap(envVarsJSON)

	// 2. Execute the job in a non-blocking goroutine (since it's an API call)
	go executeAndLogJob(job)

	// 3. Respond immediately
	respondJSON(w, http.StatusAccepted, map[string]string{"message": fmt.Sprintf("Job '%s' (ID: %s) queued for immediate execution.", job.Title, job.ID)})
}

// getJobHistoryHandler handles GET /api/jobs/{id}/history (Feature 1)
func getJobHistoryHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := getNumericJobID(jobIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	rows, err := db.Query(`SELECT id, status, startTime, duration, exitCode, output FROM job_executions WHERE jobId = ? ORDER BY startTime DESC LIMIT 10;`, numericID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	history := []JobExecution{}
	for rows.Next() {
		var exec JobExecution
		var id int
		err := rows.Scan(&id, &exec.Status, &exec.StartTime, &exec.Duration, &exec.ExitCode, &exec.Output)
		if err != nil {
			log.Printf("[ERROR] Error scanning job execution row: %v", err)
			continue
		}
		exec.ID = fmt.Sprintf("exec-%d", id)
		exec.JobID = jobIDStr
		history = append(history, exec)
	}

	respondJSON(w, http.StatusOK, history)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// --- Main Function and Routing ---

func main() {
	fmt.Printf("Version: %s, Commit: %s, Built: %s\n", version, commit, buildTime)

	// Load .env file if present
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️  No .env file found, using defaults or flags")
	}

	// Read from environment (with fallback defaults)
	defaultDBPath := getEnv("DB_PATH", "job_scheduler.db")
	defaultAdminPass := getEnv("ADMIN_PASS", "password")
	jwtKey = []byte(getEnv("JWT_TOKEN_SECRET", ""))

	// Define flags (optional override via CLI)
	dbPathPtr := flag.String("db-path", defaultDBPath, "Path to the SQLite database file for persistent storage.")
	adminPassPtr := flag.String("admin-pass", defaultAdminPass, "Set a custom admin password on startup.")
	flag.Parse()

	// Initialize the database and admin user
	if err := initializeDB(*dbPathPtr, *adminPassPtr); err != nil {
		log.Fatalf("FATAL: Database initialization failed: %v", err)
	}
	defer db.Close()

	// Start the cron scheduler initially
	startScheduler()

	// Setup Routes
	mux := http.NewServeMux()

	// Serve index.html and static files (no auth required)
	mux.HandleFunc("/", serveIndexFile)
	mux.HandleFunc("/login", loginHandler)

	// --- API Routes (Authentication required) ---
	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
		// Example URL: /api/jobs/job-123/history
		pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/jobs/"), "/")
		jobIDStr := ""
		subPath := ""

		if len(pathParts) > 0 && pathParts[0] != "" {
			jobIDStr = pathParts[0]
		}
		if len(pathParts) > 1 && pathParts[1] != "" {
			subPath = pathParts[1]
		}

		// --- Custom Routing for Job ID Sub-paths ---
		if jobIDStr != "" {
			switch subPath {
			case "run": // Feature 2: Manual Run
				if r.Method == http.MethodPost {
					runJobManuallyHandler(w, r)
					return
				}
			case "history": // Feature 1: Execution History
				if r.Method == http.MethodGet {
					getJobHistoryHandler(w, r)
					return
				}
			case "skip": // Existing Skip Execution
				if r.Method == http.MethodPost {
					skipJobHandler(w, r)
					return
				}
			case "":
				switch r.Method {
				case http.MethodDelete:
					deleteJobHandler(w, r)
					return
				case http.MethodPut:
					updateJobHandler(w, r)
					return
				}
			}
		}

		// --- Base /api/jobs/ routing ---
		if jobIDStr == "" {
			switch r.Method {
			case http.MethodGet:
				getJobsHandler(w, r)
				return
			case http.MethodPost:
				createJobHandler(w, r)
				return
			}
		}

		// Fallback for paths not matching standard patterns
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Apply authMiddleware to the API routes
	mux.Handle("/api/", authMiddleware(apiMux.ServeHTTP))

	// Wrap the main router with the CORS middleware
	handler := enableCORS(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	serverAddr := ":" + port

	log.Printf("Default user: admin")
	if *adminPassPtr != "" {
		log.Printf("Admin password successfully set via -admin-pass flag (hashed).")
	} else {
		log.Printf("Admin password is the default 'password' (hashed). Use -admin-pass flag to change.")
	}
	log.Printf("Starting server on http://localhost%s", serverAddr)
	log.Printf("PERSISTENT DATABASE FILE: %s", *dbPathPtr)

	// Server Shutdown hook (optional but good practice)
	// Ensures cron scheduler is gracefully stopped if the server is shut down
	go func() {
		// sigint := make(chan os.Signal, 1) // Uncomment if running directly on OS
		// signal.Notify(sigint, os.Interrupt)
		// <-sigint

		// For the canvas environment, this is usually handled by the runtime environment
		// but we keep the scheduler stop logic clean.

		// cronMutex.Lock()
		// if jobCron != nil {
		// 	log.Println("[SCHEDULER] Shutting down cron scheduler...")
		// 	ctx := jobCron.Stop()
		// 	<-ctx.Done()
		// }
		// cronMutex.Unlock()
	}()

	if err := http.ListenAndServe(serverAddr, handler); err != nil && err != http.ErrServerClosed {
		log.Fatalf("FATAL: Could not listen on %s: %v", serverAddr, err)
	}
}
