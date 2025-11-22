package models

import "github.com/golang-jwt/jwt/v5"

// Job defines the structure for a scheduled job.
type Job struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	CronExpression string            `json:"cronExpression"`
	ScriptContent  string            `json:"scriptContent"`
	SkipCount      int               `json:"skipCount"`
	CreatedAt      int64             `json:"createdAt"`
	UpdatedAt      int64             `json:"updatedAt,omitempty"`
	NextRunAt      int64             `json:"nextRunAt"`         // Unix milliseconds timestamp for the next run
	EnvVars        map[string]string `json:"envVars,omitempty"` // Stored as JSON string in DB
	// NotifyBeforeSeconds: number of seconds before the scheduled run to notify (0 = disabled)
	NotifyBeforeSeconds int64 `json:"notifyBeforeSeconds,omitempty"`
	// NotifyBefore: optional human-friendly input (e.g. "5m", "2h"). Accepted on create/update.
	NotifyBefore string `json:"notifyBefore,omitempty"`
	// NotifyOnExecution: if true, sends a notification after the job completes (Feature 4)
	NotifyOnExecution bool `json:"notifyOnExecution"`
}

// JobExecution defines the structure for an execution log entry (Feature 1)
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
