package main

import (
	"database/sql"
	"encoding/json"
	"errors" // REQUIRED: Added standard 'errors' package for checking specific JWT errors in v5
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
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
	// Secret key for signing the JWT. MUST be kept secret and should be loaded from environment vars in production.
	jwtKey = []byte("my_super_secret_jwt_signing_key_replace_me_in_production")
)

// --- Database Initialization and Handlers ---

// initializeDB now accepts the database file path and the desired admin password string.
func initializeDB(dbPath, adminPassword string) error {
	var err error

	// Open the database using the file path for persistence.
	// We append "?_foreign_keys=on" to ensure relational integrity is enforced.
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

	// Insert mock jobs only if the jobs table is empty (simple check for new DB)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM jobs").Scan(&count)
	if err != nil || count > 0 {
		log.Println("Database already contains job data, skipping mock data insertion.")
	} else {
		now := time.Now().UnixNano() / int64(time.Millisecond)
		mockJobs := []Job{
			{Title: "Database Backup", Description: "Run daily incremental backup.", ScriptContent: "#!/bin/bash\n...", CronExpression: "0 2 * * *", CreatedAt: now - 86400000},
			{Title: "Cache Purge", Description: "Clear old cache entries.", ScriptContent: "#!/bin/bash\n...", CronExpression: "*/30 * * * *", CreatedAt: now - 172800000},
		}
		for _, job := range mockJobs {
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
		http.Error(w, fmt.Sprintf(`{"error": "JSON marshalling error"}, %v`, err), http.StatusInternalServerError)
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
		// bcrypt.CompareHashAndPassword returns an error if the hash doesn't match
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

			// Check specifically for token expiration error using the standard errors package with JWT v5
			if errors.Is(err, jwt.ErrTokenExpired) {
				respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Token expired"})
				return
			}

			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}

		// Token is valid. We can access claims.UserID if needed later.
		log.Printf("Access granted for User ID: %s", claims.UserID)
		next.ServeHTTP(w, r)
	}
}

// --- Job Management Handlers (SQL Implementation) ---

// getJobsHandler handles GET /api/jobs.
// Changed 'r' to '_' because the request object is not needed for this handler.
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

	jobList := []Job{}
	for rows.Next() {
		var job Job
		var id int
		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt)
		if err != nil {
			log.Printf("Error scanning job row: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)
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
		respondJSON(w, http.StatusCreated, job)
		return
	}

	// UPDATE EXISTING JOB
	var jobID int
	if _, err := fmt.Sscanf(job.ID, "job-%d", &jobID); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job ID format"})
		return
	}

	result, err := db.Exec(`
		UPDATE jobs 
		SET title=?, description=?, cronExpression=?, scriptContent=?, skipCount=? 
		WHERE id=?;
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, 0, jobID) // Reset skipCount on update

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

	log.Printf("Job %s skipped. New SkipCount: %d", jobIDStr, newSkipCount)
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
	if err := initializeDB(*dbPathPtr, adminPassword); err != nil { // Pass the database path and password
		log.Fatalf("Fatal Error initializing database: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()

	// Public API Route (Login)
	mux.HandleFunc("/login", loginHandler)

	// Default route for API information
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Scheduled Job Management API is running. Access /api/jobs for authenticated endpoints."))
	})

	// Protected API Routes
	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getJobsHandler(w, r)
		case http.MethodPost:
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
	log.Printf("PERSISTENT DATABASE FILE: %s", *dbPathPtr) // Log the file path
	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
