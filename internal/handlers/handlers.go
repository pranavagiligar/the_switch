package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/pranavagiligar/the_switch/internal/config"
	"github.com/pranavagiligar/the_switch/internal/database"
	"github.com/pranavagiligar/the_switch/internal/models"
	"github.com/pranavagiligar/the_switch/internal/scheduler"
	"github.com/pranavagiligar/the_switch/internal/ui"
	"github.com/pranavagiligar/the_switch/internal/utils"
)

// ServeIndexFile serves the index.html file
func ServeIndexFile(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := ui.Content.ReadFile("index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// BuildInfoHandler exposes build metadata (version, commit, buildTime) to the frontend
func BuildInfoHandler(version, commit, buildTime string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		utils.RespondJSON(w, http.StatusOK, map[string]string{
			"version":   version,
			"commit":    commit,
			"buildTime": buildTime,
		})
	}
}

// LoginHandler handles user authentication
func LoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userLogin models.UserLogin
		if err := json.NewDecoder(r.Body).Decode(&userLogin); err != nil {
			utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
			return
		}

		var passwordHash string
		var userID int
		err := database.DB.QueryRow("SELECT id, passwordHash FROM users WHERE username = ?", userLogin.Username).Scan(&userID, &passwordHash)

		if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(userLogin.Password)) != nil {
			utils.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
			return
		}

		// Create the JWT token
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &models.Claims{
			UserID: fmt.Sprintf("%d", userID),
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(cfg.JWTKey)

		if err != nil {
			utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not create token"})
			return
		}

		utils.RespondJSON(w, http.StatusOK, map[string]string{"token": tokenString})
	}
}

// GetJobsHandler fetches jobs with optional search and sort
func GetJobsHandler(w http.ResponseWriter, r *http.Request) {
	// Support search via ?q= and sorting via ?sort=
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	sortParam := strings.TrimSpace(r.URL.Query().Get("sort"))

	baseQuery := `SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, updatedAt, envVars, notifyBeforeSeconds, notifyOnExecution FROM jobs`
	var rows *sql.Rows
	var err error
	if q != "" {
		pattern := "%" + q + "%"
		rows, err = database.DB.Query(baseQuery+` WHERE title LIKE ? OR description LIKE ?;`, pattern, pattern)
	} else {
		rows, err = database.DB.Query(baseQuery + `;`)
	}
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	scheduler.CronMutex.Lock()
	parser := scheduler.JobParser
	scheduler.CronMutex.Unlock()
	jobList := []models.Job{}
	now := time.Now()

	for rows.Next() {
		var job models.Job
		var id int
		var envVarsJSON string // Read envVars (Feature 3)
		var notifyBeforeSec int64
		var updatedAt int64
		var notifyOnExec bool
		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &updatedAt, &envVarsJSON, &notifyBeforeSec, &notifyOnExec)
		if err != nil {
			log.Printf("[ERROR] Error scanning job row for API: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

		// Deserialize envVars (Feature 3)
		job.EnvVars, _ = utils.JSONToMap(envVarsJSON)
		job.NotifyBeforeSeconds = notifyBeforeSec
		job.NotifyOnExecution = notifyOnExec
		// Populate UpdatedAt (fallback to CreatedAt if zero)
		if updatedAt == 0 {
			job.UpdatedAt = job.CreatedAt
		} else {
			job.UpdatedAt = updatedAt
		}

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

	// Apply sorting in Go
	switch sortParam {
	case "alphabetical":
		sort.Slice(jobList, func(i, j int) bool {
			return strings.ToLower(jobList[i].Title) < strings.ToLower(jobList[j].Title)
		})
	case "date_created":
		sort.Slice(jobList, func(i, j int) bool { return jobList[i].CreatedAt > jobList[j].CreatedAt })
	case "date_modified":
		sort.Slice(jobList, func(i, j int) bool { return jobList[i].UpdatedAt > jobList[j].UpdatedAt })
	case "next_schedule":
		sort.Slice(jobList, func(i, j int) bool {
			ni := jobList[i].NextRunAt
			nj := jobList[j].NextRunAt
			if ni == 0 && nj == 0 {
				return strings.ToLower(jobList[i].Title) < strings.ToLower(jobList[j].Title)
			}
			if ni == 0 {
				return false
			}
			if nj == 0 {
				return true
			}
			return ni < nj
		})
	default:
		sort.Slice(jobList, func(i, j int) bool { return jobList[i].CreatedAt > jobList[j].CreatedAt })
	}

	utils.RespondJSON(w, http.StatusOK, jobList)
}

// CreateJobHandler handles new job creation
func CreateJobHandler(w http.ResponseWriter, r *http.Request) {
	var job models.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	// 1. Serialize envVars map to JSON string (Feature 3)
	envVarsJSON, err := utils.MapToJSON(job.EnvVars)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid environment variables format"})
		return
	}

	// 2. Validate CRON
	scheduler.CronMutex.Lock()
	parser := scheduler.JobParser
	scheduler.CronMutex.Unlock()

	_, err = parser.Parse(job.CronExpression)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CRON expression: " + err.Error()})
		return
	}

	// 3. Parse NotifyBefore string (e.g. "5m") to seconds
	notifySeconds, err := utils.ParseShortDuration(job.NotifyBefore)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid notifyBefore format: " + err.Error()})
		return
	}
	job.NotifyBeforeSeconds = int64(notifySeconds.Seconds())

	// 4. Insert into DB
	now := time.Now().UnixNano() / int64(time.Millisecond)
	res, err := database.DB.Exec(`
		INSERT INTO jobs (title, description, cronExpression, scriptContent, createdAt, updatedAt, envVars, notifyBeforeSeconds, notifyOnExecution)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, now, now, envVarsJSON, job.NotifyBeforeSeconds, job.NotifyOnExecution)

	if err != nil {
		log.Printf("DB Insert Error: %v", err)
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create job"})
		return
	}

	id, _ := res.LastInsertId()
	job.ID = fmt.Sprintf("job-%d", id)
	job.CreatedAt = now
	job.UpdatedAt = now

	// 5. Refresh scheduler
	scheduler.StartScheduler()

	utils.RespondJSON(w, http.StatusOK, job)
}

// UpdateJobHandler handles job updates
func UpdateJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	var job models.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	// 1. Serialize envVars (Feature 3)
	envVarsJSON, err := utils.MapToJSON(job.EnvVars)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid environment variables format"})
		return
	}

	// 2. Validate CRON
	scheduler.CronMutex.Lock()
	parser := scheduler.JobParser
	scheduler.CronMutex.Unlock()

	_, err = parser.Parse(job.CronExpression)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CRON expression: " + err.Error()})
		return
	}

	// 3. Parse NotifyBefore string (e.g. "5m") to seconds
	notifySeconds, err := utils.ParseShortDuration(job.NotifyBefore)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid notifyBefore format: " + err.Error()})
		return
	}
	job.NotifyBeforeSeconds = int64(notifySeconds.Seconds())

	// 4. Update DB
	now := time.Now().UnixNano() / int64(time.Millisecond)
	_, err = database.DB.Exec(`
		UPDATE jobs 
		SET title=?, description=?, cronExpression=?, scriptContent=?, skipCount=?, updatedAt=?, envVars=?, notifyBeforeSeconds=?, notifyOnExecution=?
		WHERE id=?;
	`, job.Title, job.Description, job.CronExpression, job.ScriptContent, job.SkipCount, now, envVarsJSON, job.NotifyBeforeSeconds, job.NotifyOnExecution, numericID)

	if err != nil {
		log.Printf("DB Update Error: %v", err)
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update job"})
		return
	}

	job.ID = jobIDStr
	job.UpdatedAt = now

	// 5. Refresh scheduler
	scheduler.StartScheduler()

	utils.RespondJSON(w, http.StatusOK, job)
}

// DeleteJobHandler handles job deletion
func DeleteJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	_, err = database.DB.Exec("DELETE FROM jobs WHERE id = ?", numericID)
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete job"})
		return
	}

	// Refresh scheduler
	scheduler.StartScheduler()

	w.WriteHeader(http.StatusNoContent)
}

// SkipJobHandler increments the skip count for a job
func SkipJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	_, err = database.DB.Exec("UPDATE jobs SET skipCount = skipCount + 1 WHERE id = ?", numericID)
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update skip count"})
		return
	}

	var newCount int
	err = database.DB.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", numericID).Scan(&newCount)
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch updated skip count"})
		return
	}

	utils.RespondJSON(w, http.StatusOK, map[string]int{"skipCount": newCount})
}

// GetJobHandler fetches a single job
func GetJobHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	var job models.Job
	var envVarsJSON string
	var notifyBeforeSec int64
	var updatedAt int64
	var notifyOnExec bool

	err = database.DB.QueryRow(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, updatedAt, envVars, notifyBeforeSeconds, notifyOnExecution
		FROM jobs WHERE id = ?
	`, numericID).Scan(&numericID, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &updatedAt, &envVarsJSON, &notifyBeforeSec, &notifyOnExec)

	if err == sql.ErrNoRows {
		utils.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}

	job.ID = jobIDStr
	job.EnvVars, _ = utils.JSONToMap(envVarsJSON)
	job.NotifyBeforeSeconds = notifyBeforeSec
	job.NotifyOnExecution = notifyOnExec
	if updatedAt == 0 {
		job.UpdatedAt = job.CreatedAt
	} else {
		job.UpdatedAt = updatedAt
	}

	// Calculate Next Run
	scheduler.CronMutex.Lock()
	parser := scheduler.JobParser
	scheduler.CronMutex.Unlock()

	schedule, _ := parser.Parse(job.CronExpression)
	if schedule != nil {
		nextTime := schedule.Next(time.Now())
		for i := 0; i < job.SkipCount; i++ {
			nextTime = schedule.Next(nextTime)
		}
		job.NextRunAt = nextTime.UnixNano() / int64(time.Millisecond)
	}

	utils.RespondJSON(w, http.StatusOK, job)
}

// RunJobManuallyHandler handles POST /api/jobs/{id}/run (Feature 2)
func RunJobManuallyHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	// 1. Fetch job details
	var job models.Job
	var envVarsJSON string
	err = database.DB.QueryRow(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, envVars
		FROM jobs WHERE id = ?
	`, numericID).Scan(&numericID, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &envVarsJSON)

	if err == sql.ErrNoRows {
		utils.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}
	if err != nil {
		log.Printf("[DB ERROR] Failed to fetch job %s for manual run: %v", jobIDStr, err)
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch job data"})
		return
	}

	job.ID = jobIDStr
	job.EnvVars, _ = utils.JSONToMap(envVarsJSON)

	// 2. Execute the job in a non-blocking goroutine (since it's an API call)
	go scheduler.ExecuteAndLogJob(job)

	// 3. Respond immediately
	utils.RespondJSON(w, http.StatusAccepted, map[string]string{"message": fmt.Sprintf("Job '%s' (ID: %s) queued for immediate execution.", job.Title, job.ID)})
}

// GetJobHistoryHandler handles GET /api/jobs/{id}/history (Feature 1)
func GetJobHistoryHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	jobIDStr := pathParts[3]
	numericID, err := utils.GetNumericJobID(jobIDStr)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Job ID format"})
		return
	}

	rows, err := database.DB.Query(`SELECT id, status, startTime, duration, exitCode, output FROM job_executions WHERE jobId = ? ORDER BY startTime DESC LIMIT 10;`, numericID)
	if err != nil {
		utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	history := []models.JobExecution{}
	for rows.Next() {
		var exec models.JobExecution
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

	utils.RespondJSON(w, http.StatusOK, history)
}

// CronIntervalHandler accepts POST { cronExpression: string }
// and returns the interval in seconds between the next two scheduled runs.
func CronIntervalHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		CronExpression string `json:"cronExpression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid payload"})
		return
	}

	scheduler.CronMutex.Lock()
	parser := scheduler.JobParser
	scheduler.CronMutex.Unlock()

	sched, err := parser.Parse(payload.CronExpression)
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid CRON expression: " + err.Error()})
		return
	}

	now := time.Now()
	next1 := sched.Next(now)
	next2 := sched.Next(next1)
	interval := next2.Sub(next1)
	utils.RespondJSON(w, http.StatusOK, map[string]int64{"intervalSeconds": int64(interval.Seconds())})
}
