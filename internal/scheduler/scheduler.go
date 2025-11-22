package scheduler

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/pranavagiligar/the_switch/internal/database"
	"github.com/pranavagiligar/the_switch/internal/models"
	"github.com/pranavagiligar/the_switch/internal/utils"
)

var (
	// Global cron instance, mutex, and the parser instance
	JobCron   *cron.Cron
	CronMutex sync.Mutex
	JobParser cron.Parser
)

// StartScheduler fetches all jobs and sets up the cron schedule.
func StartScheduler() {
	CronMutex.Lock()
	defer CronMutex.Unlock()

	// 1. Stop the current scheduler if it's running
	if JobCron != nil {
		log.Println("[SCHEDULER] Stopping existing cron scheduler...")
		ctx := JobCron.Stop()
		<-ctx.Done() // Wait for the stop signal
	}

	// 2. Initialize a new scheduler
	newParser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	JobCron = cron.New(cron.WithParser(newParser))
	JobParser = newParser

	log.Println("[SCHEDULER] Fetching all jobs to schedule...")

	// 3. Fetch all jobs from the database (including envVars)
	rows, err := database.DB.Query(`
		SELECT id, title, description, cronExpression, scriptContent, skipCount, createdAt, envVars, notifyBeforeSeconds
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
		var job models.Job
		var id int
		var envVarsJSON string // Scan EnvVars JSON string (Feature 3)
		var notifyBeforeSec int64

		err := rows.Scan(&id, &job.Title, &job.Description, &job.CronExpression, &job.ScriptContent, &job.SkipCount, &job.CreatedAt, &envVarsJSON, &notifyBeforeSec)
		if err != nil {
			log.Printf("[ERROR] Error scanning job row for scheduling: %v", err)
			continue
		}
		job.ID = fmt.Sprintf("job-%d", id)

		// Deserialize envVars (Feature 3)
		job.EnvVars, _ = utils.JSONToMap(envVarsJSON)
		job.NotifyBeforeSeconds = notifyBeforeSec

		// Add the job to cron
		_, err = JobCron.AddFunc(job.CronExpression, runJob(job))
		if err != nil {
			log.Printf("[ERROR] Failed to schedule job %s (%s): %v", job.Title, job.CronExpression, err)
			continue
		}
		jobsScheduled++
	}

	// 5. Start the new scheduler in a background goroutine
	JobCron.Start()
	log.Printf("[SCHEDULER] Scheduler successfully restarted. %d jobs scheduled.", jobsScheduled)
}

// runJob executes the script content for a given job (called by cron).
func runJob(job models.Job) func() {
	return func() {
		log.Printf("[SCHEDULER] Job %s (ID: %s) triggered with cron: %s", job.Title, job.ID, job.CronExpression)

		// Check and handle skip count
		var currentSkipCount int
		numericID, err := utils.GetNumericJobID(job.ID)
		if err != nil {
			log.Printf("[ERROR] Failed to parse job ID in runJob: %v", err)
			return
		}

		err = database.DB.QueryRow("SELECT skipCount FROM jobs WHERE id = ?", numericID).Scan(&currentSkipCount)
		if err != nil {
			log.Printf("[ERROR] Failed to read skipCount for job %s: %v", job.ID, err)
			return
		}

		if currentSkipCount > 0 {
			// Decrement skip count and skip execution
			_, err = database.DB.Exec("UPDATE jobs SET skipCount = ? WHERE id = ?", currentSkipCount-1, numericID)
			if err != nil {
				log.Printf("[ERROR] Failed to decrement skipCount for job %s: %v", job.ID, err)
			}
			log.Printf("[SKIP] Job %s skipped. Remaining skips: %d", job.Title, currentSkipCount-1)
			return
		}

		// Execute and log the job using the shared function
		ExecuteAndLogJob(job)
	}
}

// ExecuteAndLogJob separates execution logic for re-use by scheduler and manual run handler (Feature 1 & 3)
func ExecuteAndLogJob(job models.Job) {
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
	numericID, err := utils.GetNumericJobID(job.ID)
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
	_, dbErr := database.DB.Exec(`
		INSERT INTO job_executions (jobId, status, startTime, duration, exitCode, output)
		VALUES (?, ?, ?, ?, ?, ?);
	`, numericID, status, startTime.UnixNano()/int64(time.Millisecond), duration, exitCode, string(output))

	if dbErr != nil {
		log.Printf("[DB ERROR] Failed to store execution log for job %s: %v", job.ID, dbErr)
	}
}
