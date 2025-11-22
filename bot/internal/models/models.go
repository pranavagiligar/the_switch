package models

// AuthResponse matches the login handler response in main.go
type AuthResponse struct {
	Token string `json:"token"`
}

// Job matches the Job structure in main.go, but only contains fields needed for display
type Job struct {
	ID                  string `json:"id"`
	Title               string `json:"title"`
	CronExpression      string `json:"cronExpression"`
	SkipCount           int    `json:"skipCount"`
	NextRunAt           int64  `json:"nextRunAt"`
	NotifyBeforeSeconds int64  `json:"notifyBeforeSeconds,omitempty"`
	NotifyOnExecution   bool   `json:"notifyOnExecution"`
}

// JobExecution matches the job execution structure returned by the API
type JobExecution struct {
	ID        string `json:"id"`
	JobID     string `json:"jobId"`
	Status    string `json:"status"`
	StartTime int64  `json:"startTime"`
	Duration  int64  `json:"duration"`
	ExitCode  int    `json:"exitCode"`
	Output    string `json:"output"`
}

// SkipResponse matches the skip handler response in main.go
type SkipResponse struct {
	ID        string `json:"id"`
	SkipCount int    `json:"skipCount"`
	Message   string `json:"message"`
	NextRunAt int64  `json:"nextRunAt,omitempty"`
}
