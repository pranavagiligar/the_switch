package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Job defines the structure for a scheduled job, aligned with the frontend data model.
type Job struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	CronExpression string `json:"cronExpression"`
	ScriptContent  string `json:"scriptContent"`
	SkipCount      int    `json:"skipCount"` // Critical field for skipping the next run
	CreatedAt      int64  `json:"createdAt"` // Unix timestamp for sorting
}

// Global in-memory storage for jobs, protected by a mutex.
var (
	jobs      = make(map[string]Job)
	jobsMutex sync.RWMutex
	nextJobID = 1
)

// init populates the job map with some initial mock data.
func init() {
	now := time.Now().UnixNano() / int64(time.Millisecond)

	mockJobs := []Job{
		{ID: "job-1", Title: "Database Backup", Description: "Run daily incremental backup of production database.", ScriptContent: "#!/bin/bash\necho \"Starting daily database backup...\"", CronExpression: "0 2 * * *", SkipCount: 0, CreatedAt: now - 86400000},
		{ID: "job-2", Title: "Cache Purge", Description: "Clear old cache entries from CDN and local storage.", ScriptContent: "#!/bin/bash\n/usr/bin/curl -X POST https://cdn/purge", CronExpression: "*/30 * * * *", SkipCount: 0, CreatedAt: now - 172800000},
		{ID: "job-3", Title: "Monthly Report Generation", Description: "Generate and email monthly performance metrics report.", ScriptContent: "/usr/bin/python3 /home/user/reports/monthly.py", CronExpression: "0 9 1 * *", SkipCount: 0, CreatedAt: now - 345600000},
	}

	jobsMutex.Lock()
	for _, job := range mockJobs {
		jobs[job.ID] = job
		// Update nextJobID counter
		idNum, _ := strconv.Atoi(job.ID[4:])
		if idNum >= nextJobID {
			nextJobID = idNum + 1
		}
	}
	jobsMutex.Unlock()
}

// enableCORS is middleware to set CORS headers for development simplicity.
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// respondJSON writes JSON response to the http.ResponseWriter.
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error": "JSON marshalling error: %v"}`, err)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

// getJobsHandler handles GET /api/jobs.
func getJobsHandler(w http.ResponseWriter, r *http.Request) {
	jobsMutex.RLock()
	defer jobsMutex.RUnlock()

	// Convert map to slice for sorting
	jobList := make([]Job, 0, len(jobs))
	for _, job := range jobs {
		jobList = append(jobList, job)
	}

	// Sort by CreatedAt descending (newest first), matching frontend logic
	sort.Slice(jobList, func(i, j int) bool {
		return jobList[i].CreatedAt > jobList[j].CreatedAt
	})

	respondJSON(w, http.StatusOK, jobList)
}

// createOrUpdateJobHandler handles POST /api/jobs for both creation and updates.
func createOrUpdateJobHandler(w http.ResponseWriter, r *http.Request) {
	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid job data"})
		return
	}

	jobsMutex.Lock()
	defer jobsMutex.Unlock()

	if job.ID == "" {
		// CREATE NEW JOB
		job.ID = fmt.Sprintf("job-%d", nextJobID)
		nextJobID++
		job.CreatedAt = time.Now().UnixNano() / int64(time.Millisecond)
		job.SkipCount = 0 // Ensure new jobs start with 0 skips
		jobs[job.ID] = job
		respondJSON(w, http.StatusCreated, job)
		return
	}

	// UPDATE EXISTING JOB
	if existingJob, ok := jobs[job.ID]; ok {
		// Only update mutable fields, preserve CreatedAt
		existingJob.Title = job.Title
		existingJob.Description = job.Description
		existingJob.CronExpression = job.CronExpression
		existingJob.ScriptContent = job.ScriptContent
		// When updating the job details, we reset the skip count
		existingJob.SkipCount = 0

		jobs[existingJob.ID] = existingJob
		respondJSON(w, http.StatusOK, existingJob)
		return
	}

	respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found for update"})
}

// deleteJobHandler handles DELETE /api/jobs/{id}.
func deleteJobHandler(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Path[len("/api/jobs/"):]

	jobsMutex.Lock()
	defer jobsMutex.Unlock()

	if _, ok := jobs[jobID]; !ok {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}

	delete(jobs, jobID)
	respondJSON(w, http.StatusNoContent, nil) // 204 No Content for successful deletion
}

// skipJobHandler handles POST /api/jobs/{id}/skip.
// This is the new endpoint to increment the SkipCount.
func skipJobHandler(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Path[len("/api/jobs/") : len(r.URL.Path)-len("/skip")]

	jobsMutex.Lock()
	defer jobsMutex.Unlock()

	job, ok := jobs[jobID]
	if !ok {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "Job not found"})
		return
	}

	// Increment the skip count
	job.SkipCount++
	jobs[jobID] = job

	log.Printf("Job %s skipped. New SkipCount: %d", jobID, job.SkipCount)
	respondJSON(w, http.StatusOK, job)
}

// main sets up the router and starts the server.
func main() {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getJobsHandler(w, r)
		case http.MethodPost:
			// POST is used for both create (ID="") and update (ID!="").
			createOrUpdateJobHandler(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
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

		// Fallback for other methods/paths
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Wrap the router with the CORS middleware
	handler := enableCORS(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	serverAddr := ":" + port

	log.Printf("Starting server on http://localhost%s", serverAddr)
	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
