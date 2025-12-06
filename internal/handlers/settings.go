package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/pranavagiligar/the_switch/internal/database"
	"github.com/pranavagiligar/the_switch/internal/models"
	"github.com/pranavagiligar/the_switch/internal/scheduler"
	"github.com/pranavagiligar/the_switch/internal/utils"
)

// ExportData defines the structure of the exported configuration file
type ExportData struct {
	Version    string       `json:"version"`
	ExportedAt string       `json:"exportedAt"`
	Jobs       []models.Job `json:"jobs"`
}

// ExportConfigurationHandler handles GET /api/settings/export
// It dumps all jobs into a JSON file for download, wrapping them in ExportData.
func ExportConfigurationHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Fetch all jobs
		rows, err := database.DB.Query(`
			SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, updatedAt, envVars, notifyBeforeSeconds, notifyOnExecution 
			FROM jobs
		`)
		if err != nil {
			utils.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database query failed"})
			return
		}
		defer rows.Close()

		var jobs []models.Job
		for rows.Next() {
			var job models.Job
			var id int
			var envVarsJSON string
			var notifyBeforeSec int64
			var updatedAt int64
			var notifyOnExec bool
			err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &updatedAt, &envVarsJSON, &notifyBeforeSec, &notifyOnExec)
			if err != nil {
				log.Printf("[EXPORT] Error scanning job: %v", err)
				continue
			}
			job.ID = fmt.Sprintf("job-%d", id)
			job.EnvVars, _ = utils.JSONToMap(envVarsJSON)
			job.NotifyBeforeSeconds = notifyBeforeSec
			job.NotifyOnExecution = notifyOnExec
			job.UpdatedAt = updatedAt
			if job.UpdatedAt == 0 {
				job.UpdatedAt = job.CreatedAt
			}

			jobs = append(jobs, job)
		}

		// 2. Prepare Export Data
		exportData := ExportData{
			Version:    version,
			ExportedAt: time.Now().Format(time.RFC3339),
			Jobs:       jobs,
		}

		// 3. Set headers for file download
		filename := fmt.Sprintf("the_switch_config_%s.json", time.Now().Format("20060102_150405"))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.Header().Set("Content-Type", "application/json")

		// 4. Encoder to ResponseWriter
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(exportData); err != nil {
			log.Printf("[EXPORT] Encoding error: %v", err)
		}
	}
}

// ImportConfigurationHandler handles POST /api/settings/import
// Expects a multipart file upload with key "configFile"
func ImportConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Limit upload size (e.g., 10MB)
	r.ParseMultipartForm(10 << 20)

	file, _, err := r.FormFile("configFile")
	if err != nil {
		utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid file upload"})
		return
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)

	// Decode JSON
	// Try to decode as new format (ExportData) first
	var exportData ExportData
	var jobs []models.Job

	// We use a raw map check or try/error.
	// Let's try to unmarshal into ExportData. If Jobs is empty but the file is not empty, check if it was an array.
	if err := json.Unmarshal(byteValue, &exportData); err != nil || len(exportData.Jobs) == 0 {
		// Fallback: Try decoding as pure array (Legacy support)
		// Reset valid jobs list incase Unmarshal partially worked
		var legacyJobs []models.Job
		if errLegacy := json.Unmarshal(byteValue, &legacyJobs); errLegacy == nil && len(legacyJobs) > 0 {
			jobs = legacyJobs
			log.Println("[IMPORT] detected legacy formatting (array of jobs)")
		} else {
			// If both failed (and ExportData.Jobs is empty), it might be a valid empty ExportData or invalid file.
			// But if Unmarshal returned error for ExportData, check legacy.
			if err != nil && len(legacyJobs) == 0 {
				utils.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON format or empty file."})
				return
			}
			// If ExportData unmarshal worked but jobs empty, it's just 0 jobs.
			// If it failed but legacy worked, we use legacy.
			if len(exportData.Jobs) > 0 {
				jobs = exportData.Jobs
			}
		}
	} else {
		jobs = exportData.Jobs
	}

	// Double check if we failed to get any jobs and didn't error out
	if len(jobs) == 0 && len(exportData.Jobs) == 0 {
		// Try one last check if the file was just "[]"
		var legacyJobs []models.Job
		if json.Unmarshal(byteValue, &legacyJobs) == nil {
			jobs = legacyJobs
		}
	}

	if len(jobs) == 0 {
		utils.RespondJSON(w, http.StatusOK, map[string]string{"message": "No jobs found in the import file."})
		return
	}

	successCount := 0
	failCount := 0

	// Insert Jobs
	for _, job := range jobs {
		// Serialize EnvVars
		envVarsJSON, _ := utils.MapToJSON(job.EnvVars)

		// If CreatedAt/UpdatedAt are 0/missing, set to now
		now := time.Now().UnixNano() / int64(time.Millisecond)
		if job.CreatedAt == 0 {
			job.CreatedAt = now
		}
		if job.UpdatedAt == 0 {
			job.UpdatedAt = now
		}

		// Insert (ignoring original ID)
		_, err := database.DB.Exec(`
			INSERT INTO jobs (title, description, cronExpression, scriptContent, skipCount, createdAt, updatedAt, envVars, notifyBeforeSeconds, notifyOnExecution)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
		`, job.Title, job.Description, job.CronExpression, job.ScriptContent, job.SkipCount, job.CreatedAt, job.UpdatedAt, envVarsJSON, job.NotifyBeforeSeconds, job.NotifyOnExecution)

		if err != nil {
			log.Printf("[IMPORT] Failed to insert job '%s': %v", job.Title, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Refresh Scheduler
	scheduler.StartScheduler()

	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message":      fmt.Sprintf("Import completed. Success: %d, Failed: %d", successCount, failCount),
		"successCount": successCount,
		"failCount":    failCount,
	})
}
