package poller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/pranavagiligar/the_switch_bot/internal/api"
	"github.com/pranavagiligar/the_switch_bot/internal/config"
	"github.com/pranavagiligar/the_switch_bot/internal/models"
	"github.com/pranavagiligar/the_switch_bot/internal/utils"
)

var (
	// scheduledNotifications keeps track of the last NextRunAt we scheduled a notification for
	scheduledNotifications = make(map[string]int64)
	schedNotifMutex        sync.Mutex

	// lastSeenExecution keeps track of the last execution ID we notified for each job
	lastSeenExecution = make(map[string]string)
	executionMutex    sync.Mutex
)

// PollJobExecutions periodically checks job execution history and sends Telegram notifications
func PollJobExecutions(bot *tgbotapi.BotAPI, client *api.Client, cfg *config.Config) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C

		// Fetch all jobs to check their execution history
		resp, err := client.Call("GET", "/api/jobs/", nil)
		if err != nil {
			log.Printf("[EXEC_NOTIFY] failed to fetch jobs: %v", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[EXEC_NOTIFY] API returned non-OK: %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		var jobs []models.Job
		if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
			resp.Body.Close()
			log.Printf("[EXEC_NOTIFY] decode failed: %v", err)
			continue
		}
		resp.Body.Close()

		for _, job := range jobs {
			// Fetch execution history for this job
			hresp, herr := client.Call("GET", "/api/jobs/"+job.ID+"/history?limit=1", nil)
			if herr != nil {
				log.Printf("[EXEC_NOTIFY] failed to fetch history for job %s: %v", job.ID, herr)
				continue
			}
			if hresp.StatusCode != http.StatusOK {
				log.Printf("[EXEC_NOTIFY] API returned non-OK for history: %d", hresp.StatusCode)
				hresp.Body.Close()
				continue
			}

			var hist []models.JobExecution
			if err := json.NewDecoder(hresp.Body).Decode(&hist); err != nil {
				hresp.Body.Close()
				log.Printf("[EXEC_NOTIFY] decode history failed for job %s: %v", job.ID, err)
				continue
			}
			hresp.Body.Close()

			if len(hist) == 0 {
				continue
			}

			// Get the most recent execution
			latestExec := hist[0]

			executionMutex.Lock()
			lastID := lastSeenExecution[job.ID]
			executionMutex.Unlock()

			// Skip if we've already notified about this execution
			if lastID == latestExec.ID {
				continue
			}

			// Check if notifications are enabled for this job (Feature 4)
			if !job.NotifyOnExecution {
				// Even if disabled, we should mark it as seen so we don't spam if enabled later
				executionMutex.Lock()
				lastSeenExecution[job.ID] = latestExec.ID
				executionMutex.Unlock()
				continue
			}

			// Only notify for completed executions (status = "Success" or "Failure")
			if latestExec.Status != "Success" && latestExec.Status != "Failure" {
				continue
			}

			// Mark this execution as notified
			executionMutex.Lock()
			lastSeenExecution[job.ID] = latestExec.ID
			executionMutex.Unlock()

			// Determine pass/fail emoji and status text
			statusEmoji := "✅"
			statusText := "succeeded"
			if latestExec.Status == "Failure" || latestExec.ExitCode != 0 {
				statusEmoji = "❌"
				statusText = "failed"
			}

			// Format next run time
			nextRunText := "Unknown"
			if job.NextRunAt != 0 {
				nextRunText = time.Unix(0, job.NextRunAt*int64(time.Millisecond)).Format("Jan 2, 2006 15:04:05 MST")
			} else {
				nextRunText = "No scheduled run"
			}

			// Build execution notification message
			msgText := fmt.Sprintf(
				"%s **Job Execution Report**\n\n"+
					"*Job Name:* %s\n"+
					"*Job ID:* `%s`\n"+
					"*Status:* %s\n"+
					"*Exit Code:* %d\n"+
					"*Duration:* %dms\n"+
					"*Next Scheduled:* %s",
				statusEmoji,
				utils.EscapeMarkdown(job.Title),
				job.ID,
				statusText,
				latestExec.ExitCode,
				latestExec.Duration,
				nextRunText,
			)

			log.Printf("[EXEC_NOTIFY] Sending execution notification for job %s (execution %s)", job.ID, latestExec.ID)
			utils.SendMarkdown(bot, cfg.AuthorizedUserID, msgText)
		}
	}
}

// PollAndScheduleNotifications periodically fetches jobs and schedules pre-run notifications
func PollAndScheduleNotifications(bot *tgbotapi.BotAPI, client *api.Client, cfg *config.Config) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C

		resp, err := client.Call("GET", "/api/jobs/", nil)
		if err != nil {
			log.Printf("[NOTIFY] failed to fetch jobs: %v", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[NOTIFY] API returned non-OK: %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		var jobs []models.Job
		if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
			resp.Body.Close()
			log.Printf("[NOTIFY] decode failed: %v", err)
			continue
		}
		resp.Body.Close()

		now := time.Now()
		for _, job := range jobs {
			if job.NotifyBeforeSeconds <= 0 || job.NextRunAt <= 0 {
				continue
			}

			// 🕒 Use correct unit
			nextRun := time.Unix(0, job.NextRunAt*int64(time.Millisecond))
			// OR: nextRun := time.Unix(job.NextRunAt, 0)

			notifyAt := nextRun.Add(-time.Duration(job.NotifyBeforeSeconds) * time.Second)

			schedNotifMutex.Lock()
			lastScheduledNext := scheduledNotifications[job.ID]
			schedNotifMutex.Unlock()

			if lastScheduledNext == job.NextRunAt {
				continue
			}

			log.Printf("[NOTIFY] job=%s now=%v notifyAt=%v nextRun=%v",
				job.ID, now, notifyAt, nextRun)

			if now.After(notifyAt) && now.Before(nextRun) {
				schedNotifMutex.Lock()
				scheduledNotifications[job.ID] = job.NextRunAt
				schedNotifMutex.Unlock()

				go func(j models.Job) {
					// Include both Job ID and Job Title in the reminder message (with escaped title)
					msg := fmt.Sprintf("⏰ Reminder: Job `%s` (%s) is scheduled to run at %s (in %s).",
						j.ID, utils.EscapeMarkdown(j.Title), nextRun.Format("15:04:05"), time.Until(nextRun).Truncate(time.Second))
					utils.SendMarkdown(bot, cfg.AuthorizedUserID, msg)
				}(job)
				continue
			}

			if notifyAt.After(now) {
				delay := time.Until(notifyAt)
				schedNotifMutex.Lock()
				scheduledNotifications[job.ID] = job.NextRunAt
				schedNotifMutex.Unlock()

				log.Printf("[NOTIFY] scheduling job=%s in %v", job.ID, delay)
				j := job
				time.AfterFunc(delay, func() {
					// Include both Job ID and Job Title in the scheduled reminder (with escaped title)
					msg := fmt.Sprintf("⏰ Reminder: Job `%s` (%s) will run at %s (in %s).",
						j.ID, utils.EscapeMarkdown(j.Title), nextRun.Format("15:04:05"), time.Until(nextRun).Truncate(time.Second))
					utils.SendMarkdown(bot, cfg.AuthorizedUserID, msg)
				})
			}
		}
	}
}
