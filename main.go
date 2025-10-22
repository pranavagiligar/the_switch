package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
)

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
	jwtKey = []byte("my_super_secret_jwt_signing_key_replace_me_in_production")

	// Global cron instance, mutex, and the parser instance (FIXED: now accessible)
	jobCron   *cron.Cron
	cronMutex sync.Mutex
	jobParser cron.Parser // NEW: Global variable to hold the initialized cron parser
)

// serveIndexFile handles requests to the root path and serves the external index.html file.
func serveIndexFile(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "index.html")
}

// --- Scheduler and Execution Logic ---

// runJob executes the script content for a given job.
func runJob(job Job) func() {
	return func() {
		log.Printf("[SCHEDULER] Job %s (ID: %s) triggered with cron: %s", job.Title, job.ID, job.CronExpression)

		// Check and handle skip count
		var currentSkipCount int
		// Extract numeric ID from "job-ID" format
		var numericID int
		fmt.Sscanf(job.ID, "job-%d", &numericID)

		err := db.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", numericID).Scan(&currentSkipCount)
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

		// Execute the script using /bin/bash -c
		cmd := exec.Command("/bin/bash", "-c", job.ScriptContent)
		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("[EXECUTION FAILED] Job %s failed: %v\nOutput:\n%s", job.Title, err, string(output))
		} else {
			log.Printf("[EXECUTION SUCCESS] Job %s finished.\nOutput:\n%s", job.Title, string(output))
		}
	}
}

// startScheduler fetches all jobs and sets up the cron schedule.
// This function should be called after any job CRUD operation.
func startScheduler() {
	cronMutex.Lock()
	defer cronMutex.Unlock()

	// 1. Stop the current scheduler if it's running
	if jobCron != nil {
		log.Println("[SCHEDULER] Stopping existing cron scheduler...")
		// Use a context to wait for running jobs to finish, with a timeout
		ctx := jobCron.Stop()
		<-ctx.Done() // Wait for the stop signal
	}

	// 2. Initialize a new scheduler with custom second-level parser
	// Standard cron has 5 fields. The 'WithSeconds()' option adds the 6th, which is needed for some cron definitions.
	newParser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	jobCron = cron.New(cron.WithParser(newParser))
	jobParser = newParser // FIX: Store the initialized parser instance globally

	log.Println("[SCHEDULER] Fetching all jobs to schedule...")

	// 3. Fetch all jobs from the database
	rows, err := db.Query(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt 
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
		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt)
		if err != nil {
			log.Printf("[ERROR] Error scanning job row for scheduling: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

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

// --- Database Initialization and Handlers ---

// initializeDB initializes the SQLite database, creates tables, and sets up the default admin user.
func initializeDB(dbPath, adminPassword string) error {
	var err error

	// Open the database for persistence.
	db, err = sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return fmt.Errorf("error opening persistent database at %s: %w", dbPath, err)
	}

	// Create Jobs table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			cronExpression TEXT NOT NULL,
			scriptContent TEXT NOT NULL,
			skipCount INTEGER DEFAULT 0,
			createdAt INTEGER NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating jobs table: %w", err)
	}

	// Create Users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}

	// Hash the provided admin password (or the default one)
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing default password: %w", err)
	}

	// Insert the admin user with the hashed password
	_, err = db.Exec(`
		INSERT OR IGNORE INTO users (id, username, password) VALUES (?, ?, ?);
	`, 1, "admin", string(hash)) // Store the hash as a string
	if err != nil {
		return fmt.Errorf("error inserting default user: %w", err)
	}

	// Insert mock jobs only if the jobs table is empty
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM jobs").Scan(&count)
	if err != nil || count > 0 {
		log.Println("Database already contains job data, skipping mock data insertion.")
	} else {
		now := time.Now().UnixNano() / int64(time.Millisecond)
		// NOTE: Updated mock jobs to use 6-part cron for seconds-level timing
		mockJobs := []Job{
			{Title: "Heartbeat Check (Every 10s)", Description: "Simple log every 10 seconds for testing.", ScriptContent: "#!/bin/bash\necho \"Heartbeat at $(date)\"", CronExpression: "*/10 * * * * *", CreatedAt: now - 86400000},
			{Title: "Cache Purge (Daily)", Description: "Simulate clearing cache entries daily at 2:00 AM.", ScriptContent: "#!/bin/bash\n/usr/local/bin/clear_cache.sh", CronExpression: "0 0 2 * * *", CreatedAt: now - 172800000}, // Changed to 6 fields
		}
		for _, job := range mockJobs {
			// Note: using 6-part cron for seconds-level timing in the mock data
			_, err = db.Exec(`
				INSERT INTO jobs (title, description, cronExpression, scriptContent, createdAt) 
				VALUES (?, ?, ?, ?, ?);
			`, job.Title, job.Description, job.CronExpression, job.ScriptContent, job.CreatedAt)
			if err != nil {
				log.Printf("Failed to insert mock job: %v", err)
			}
		}
	}

	log.Printf("Database initialized successfully. Using persistent file: %s", dbPath)
	return nil
}

// --- Utility Functions ---

// enableCORS is middleware to set CORS headers.
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// respondJSON writes JSON response.
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		// FIX: Corrected fmt.Sprintf to include %v for error argument
		http.Error(w, fmt.Sprintf(`{"error": "JSON marshalling error: %v"}`, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

// --- Authentication Handlers and Middleware (JWT & Bcrypt) ---

// loginHandler handles POST /login.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData UserLogin
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid login request"})
		return
	}

	var storedID int
	var storedHash string

	// Fetch ID and Hash
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", loginData.Username).Scan(&storedID, &storedHash)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}
	if err != nil {
		log.Printf("DB Query Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}

	// Compare password against the stored hash using bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(loginData.Password))
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	// Authentication successful: create JWT token
	userID := strconv.Itoa(storedID)
	// Token valid for 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		log.Printf("JWT Sign Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create token"})
		return
	}

	log.Printf("User %s logged in. JWT generated.", loginData.Username)
	respondJSON(w, http.StatusOK, map[string]string{"token": tokenString, "message": "Login successful"})
}

// authMiddleware checks for a valid JWT in the Authorization header.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Authorization token required"})
			return
		}

		tokenString := authHeader[7:]

		claims := &Claims{}

		// Parse and validate JWT
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			log.Printf("Token validation failed: %v", err)

			if errors.Is(err, jwt.ErrTokenExpired) {
				respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Token expired"})
				return
			}

			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}

		next.ServeHTTP(w, r)
	}
}

// --- Job Management Handlers (SQL Implementation) ---

// getJobsHandler handles GET /api/jobs.
func getJobsHandler(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt 
		FROM jobs 
		ORDER BY createdAt DESC;
	`)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	// FIX: Use the global jobParser instance
	cronMutex.Lock()
	parser := jobParser
	cronMutex.Unlock()

	jobList := []Job{}
	now := time.Now()

	for rows.Next() {
		var job Job
		var id int
		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt)
		if err != nil {
			log.Printf("Error scanning job row: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

		// Calculate the next run time
		schedule, parseErr := parser.Parse(job.CronExpression)
		if parseErr != nil {
			log.Printf("[ERROR] Failed to parse cron expression '%s' for job %s: %v", job.CronExpression, job.ID, parseErr)
			job.NextRunAt = 0 // Indicate failure/unknown
		} else {
			nextTime := schedule.Next(now)
			// Convert time.Time to Unix milliseconds for the frontend
			job.NextRunAt = nextTime.UnixNano() / int64(time.Millisecond)
		}

		jobList = append(jobList, job)
	}

	respondJSON(w, http.StatusOK, jobList)
}

// createOrUpdateJobHandler handles POST /api/jobs.
func createOrUpdateJobHandler(w http.ResponseWriter, r *http.Request) {
	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	// Basic validation: ensure the cron expression is valid *before* saving
	// FIX: Use the global jobParser instance
	cronMutex.Lock()
	parser := jobParser
	cronMutex.Unlock()

	if _, err := parser.Parse(job.CronExpression); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid CRON expression: %v", err)})
		return
	}

	if job.ID == "" {
		// CREATE NEW JOB
		res, err := db.Exec(`
			INSERT INTO jobs (title, description, cronExpression, scriptContent, skipCount, createdAt) 
			VALUES (?, ?, ?, ?, ?, ?);
		`, job.Title, job.Description, job.CronExpression, job.ScriptContent, 0, time.Now().UnixNano()/int64(time.Millisecond))

		if err != nil {
			log.Printf("SQL Insert Error: %v", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create job"})
			return
		}

		id, _ := res.LastInsertId()
		job.ID = fmt.Sprintf("job-%d", id)
		job.CreatedAt = time.Now().UnixNano() / int64(time.Millisecond) // Approximate for response

		// RELOAD SCHEDULER
		go startScheduler()

		respondJSON(w, http.StatusCreated, job)
		return
	}

	// UPDATE EXISTING JOB
	var jobID int
	if _, err := fmt.Sscanf(job.ID, "job-%d", &jobID); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job ID format"})
		return
	}

	// Reset skipCount on update
	result, err := db.Exec(`
		UPDATE jobs 
		SET title=?, description=?, cronExpression=?, scriptContent=?, skipCount=? 
		WHERE id=?;
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, 0, jobID)

	if err != nil {
		log.Printf("SQL Update Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update job"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found for update"})
		return
	}

	// RELOAD SCHEDULER
	go startScheduler()

	respondJSON(w, http.StatusOK, job)
}

// deleteJobHandler handles DELETE /api/jobs/{id}.
func deleteJobHandler(w http.ResponseWriter, r *http.Request) {
	jobIDStr := r.URL.Path[len("/api/jobs/"):]

	var jobID int
	if _, err := fmt.Sscanf(jobIDStr, "job-%d", &jobID); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job ID format"})
		return
	}

	result, err := db.Exec("DELETE FROM jobs WHERE id = ?", jobID)
	if err != nil {
		log.Printf("SQL Delete Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete job"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}

	// RELOAD SCHEDULER
	go startScheduler()

	w.WriteHeader(http.StatusNoContent)
}

// skipJobHandler handles POST /api/jobs/{id}/skip.
func skipJobHandler(w http.ResponseWriter, r *http.Request) {
	jobIDStr := r.URL.Path[len("/api/jobs/") : len(r.URL.Path)-len("/skip")]

	var jobID int
	if _, err := fmt.Sscanf(jobIDStr, "job-%d", &jobID); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job ID format"})
		return
	}

	// Read current skip count and increment
	var currentSkipCount int
	err := db.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", jobID).Scan(&currentSkipCount)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}
	if err != nil {
		log.Printf("SQL Select Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read job data"})
		return
	}

	newSkipCount := currentSkipCount + 1

	result, err := db.Exec("UPDATE jobs SET skipCount = ? WHERE id = ?", newSkipCount, jobID)

	if err != nil {
		log.Printf("SQL Update Error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update skip count"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found after check"})
		return
	}

	// NOTE: The scheduler relies on the DB state, so we don't need to reload cron here,
	// but we should ensure the front-end sees the updated skip count.

	log.Printf("Job %s skip count incremented to %d", jobIDStr, newSkipCount)
	respondJSON(w, http.StatusOK, map[string]interface{}{"id": jobIDStr, "skipCount": newSkipCount})
}

// main sets up the database, router, and starts the server.
func main() {
	// 1. Define and parse command-line flags
	dbPathPtr := flag.String("db-path", "jobs.db", "Path to the SQLite database file for persistent storage.")
	adminPassPtr := flag.String("admin-pass", "", "Set the initial password for the 'admin' user.")
	flag.Parse()

	// 2. Determine the admin password, falling back to default if the flag is empty
	adminPassword := *adminPassPtr
	if adminPassword == "" {
		adminPassword = "password" // Fallback to hardcoded default if flag is not set
		log.Println("--- WARNING: Using default password 'password' for admin. Use -admin-pass flag for production. ---")
	}

	// 3. Initialize the persistent database
	if err := initializeDB(*dbPathPtr, adminPassword); err != nil {
		log.Fatalf("Fatal Error initializing database: %v", err)
	}
	defer db.Close()

	// 4. Initialize and start the job scheduler immediately
	startScheduler()

	mux := http.NewServeMux()

	// Public API Route (Login)
	mux.HandleFunc("/login", loginHandler)

	// Root route to serve the external HTML file
	mux.HandleFunc("/", serveIndexFile)

	// Protected API Routes setup
	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getJobsHandler(w, r)
		case http.MethodPost: // Handles both Create and Update
			createOrUpdateJobHandler(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	apiMux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
		// Check for specific skip path
		if len(r.URL.Path) > len("/api/jobs/") && r.URL.Path[len(r.URL.Path)-len("/skip"):] == "/skip" {
			if r.Method == http.MethodPost {
				skipJobHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Handle DELETE for a specific job ID
		if r.Method == http.MethodDelete {
			deleteJobHandler(w, r)
			return
		}

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
		sigint := make(chan os.Signal, 1)
		// signal.Notify(sigint, os.Interrupt) // uncomment if running directly on OS
		<-sigint
		log.Println("Shutting down scheduler...")
		ctx := jobCron.Stop()
		<-ctx.Done()
		log.Println("Scheduler stopped. Server exiting.")
		os.Exit(0)
	}()

	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
