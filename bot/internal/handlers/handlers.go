package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/pranavagiligar/the_switch_bot/internal/api"
	"github.com/pranavagiligar/the_switch_bot/internal/config"
	"github.com/pranavagiligar/the_switch_bot/internal/models"
	"github.com/pranavagiligar/the_switch_bot/internal/utils"
)

// HandleStart sends the welcome message and instructions
func HandleStart(bot *tgbotapi.BotAPI, update tgbotapi.Update, cfg *config.Config) {
	// A simple helper function to generate the common help text
	helpText := fmt.Sprintf(
		"👋 **Welcome to The Switch Bot!**\n\n"+
			"This bot helps you manage your *Scheduled Job Manager* running at: `%s`\n\n"+
			"### Commands\n"+
			"• /list - List all scheduled jobs.\n"+
			"• /skip <id> - Skip the next scheduled run for a specific job ID.\n"+
			"• /run <id> - Manually trigger a job to run immediately.\n"+
			"• /hist <job-id> [n] - Show recent execution history for a job (default last 1).\n"+
			"• /help - Show this message.\n\n"+
			"Your Telegram ID: `%d`\n",
		cfg.APIBaseURL,
		update.Message.Chat.ID,
	)

	msg := tgbotapi.NewMessage(update.Message.Chat.ID, helpText)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

// HandleList fetches and displays all scheduled jobs
func HandleList(bot *tgbotapi.BotAPI, update tgbotapi.Update, client *api.Client) {
	resp, err := client.Call("GET", "/api/jobs/", nil)
	if err != nil {
		utils.SendError(bot, update.Message.Chat.ID, "Failed to connect to API or authenticate.", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		utils.SendApiError(bot, update.Message.Chat.ID, "API returned an error while fetching jobs.", resp)
		return
	}

	var jobs []models.Job
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		utils.SendError(bot, update.Message.Chat.ID, "Failed to parse API response for jobs list.", err)
		return
	}

	if len(jobs) == 0 {
		utils.SendPlain(bot, update.Message.Chat.ID, "✅ No jobs are currently scheduled.")
		return
	}

	// Sort jobs by NextRunAt time (soonest first)
	// Use stable sort to maintain order of jobs with same NextRunAt
	for i := 0; i < len(jobs)-1; i++ {
		for j := 0; j < len(jobs)-i-1; j++ {
			// Jobs with NextRunAt = 0 (invalid CRON) go to the end
			if (jobs[j].NextRunAt == 0 && jobs[j+1].NextRunAt != 0) ||
				(jobs[j].NextRunAt > jobs[j+1].NextRunAt && jobs[j+1].NextRunAt != 0) {
				jobs[j], jobs[j+1] = jobs[j+1], jobs[j]
			}
		}
	}

	var message strings.Builder
	message.WriteString("*📋 Scheduled Jobs*\n\n")

	for _, job := range jobs {
		// Convert NextRunAt from Unix milliseconds to readable format
		nextRunTime := time.Unix(0, job.NextRunAt*int64(time.Millisecond)).Format("Jan 2, 2006 15:04:05 MST")
		if job.NextRunAt == 0 {
			nextRunTime = "Invalid CRON"
		}

		message.WriteString(fmt.Sprintf(
			"*ID:* `%s`\n"+
				"*Title:* %s\n"+
				"*Cron:* `%s`\n"+
				"*Next:* %s\n"+
				"*Skips:* %d\n"+
				"`/hist %[1]s`  •  `/run %[1]s`  •  `/skip %[1]s`\n\n",
			job.ID,
			job.Title,
			job.CronExpression,
			nextRunTime,
			job.SkipCount,
		))
	}

	utils.SendMarkdown(bot, update.Message.Chat.ID, message.String())
}

// HandleSkip skips the next execution of a specified job
func HandleSkip(bot *tgbotapi.BotAPI, update tgbotapi.Update, client *api.Client) {
	jobID := update.Message.CommandArguments()
	if jobID == "" {
		utils.SendPlain(bot, update.Message.Chat.ID, "❌ Please specify a Job ID. Usage: /skip job-1")
		return
	}

	resp, err := client.Call("POST", "/api/jobs/"+jobID+"/skip", nil)
	if err != nil {
		utils.SendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to connect or authenticate to skip job `%s`.", jobID), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		utils.SendApiError(bot, update.Message.Chat.ID, fmt.Sprintf("API returned an error while skipping job `%s`.", jobID), resp)
		return
	}

	var skipRes models.SkipResponse
	if err := json.NewDecoder(resp.Body).Decode(&skipRes); err != nil {
		utils.SendError(bot, update.Message.Chat.ID, "Failed to parse API response for skip operation.", err)
		return
	}

	// Try to fetch job details so we can include the Job Title in the response
	jobTitle := ""
	var nextRunAt int64
	jresp, jerr := client.Call("GET", "/api/jobs/"+jobID, nil)
	if jerr == nil && jresp != nil {
		defer jresp.Body.Close()
		if jresp.StatusCode == http.StatusOK {
			var j models.Job
			if err := json.NewDecoder(jresp.Body).Decode(&j); err == nil {
				jobTitle = j.Title
				nextRunAt = j.NextRunAt
			}
		}
	}

	if jobTitle == "" {
		jobTitle = "(unknown)"
	}

	// Format next run time for human readable output
	nextRun := "Unknown"

	// Use nextRunAt from job details if available, otherwise fallback to skip response
	valToFormat := skipRes.NextRunAt
	if nextRunAt != 0 {
		valToFormat = nextRunAt
	}

	if valToFormat != 0 {
		nextRun = time.Unix(0, valToFormat*int64(time.Millisecond)).Format("Jan 2, 2006 15:04:05 MST")
	} else {
		nextRun = "No scheduled run"
	}

	// Include Job Title along with Job ID, Next schedule and Skip count
	msgText := fmt.Sprintf(
		"✅ **Job Successfully Skipped**\n\n"+
			"*Job Name:* %s\n"+
			"*Job ID:* `%s`\n"+
			"*Next Schedule:* %s\n"+
			"*New Skip Count:* %d",
		utils.EscapeMarkdown(jobTitle),
		jobID,
		nextRun,
		skipRes.SkipCount,
	)
	utils.SendMarkdown(bot, update.Message.Chat.ID, msgText)
}

// HandleRun manually triggers a specified job
func HandleRun(bot *tgbotapi.BotAPI, update tgbotapi.Update, client *api.Client) {
	jobID := update.Message.CommandArguments()
	if jobID == "" {
		utils.SendPlain(bot, update.Message.Chat.ID, "❌ Please specify a Job ID. Usage: /run job-1")
		return
	}

	// NOTE: This uses the new /run endpoint implemented in main.go (Feature 2)
	resp, err := client.Call("POST", "/api/jobs/"+jobID+"/run", nil)
	if err != nil {
		utils.SendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to connect or authenticate to run job `%s`.", jobID), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		utils.SendPlain(bot, update.Message.Chat.ID, fmt.Sprintf("⚡ Job `%s` queued for immediate execution! Check the web UI for logs.", jobID))
	} else {
		utils.SendApiError(bot, update.Message.Chat.ID, fmt.Sprintf("API returned an error while trying to run job `%s`.", jobID), resp)
	}
}

// HandleHist fetches recent execution history across all jobs and displays
// the last N entries (default 10). Usage: /hist or /hist 5
func HandleHist(bot *tgbotapi.BotAPI, update tgbotapi.Update, client *api.Client) {
	// Expect arguments: jobID [n]
	args := strings.Fields(strings.TrimSpace(update.Message.CommandArguments()))
	if len(args) == 0 {
		utils.SendPlain(bot, update.Message.Chat.ID, "❌ Usage: /hist <job-id> [n]\nExample: /hist job-1 5")
		return
	}

	jobID := args[0]
	limit := 1 // default per your request: show 1 last history if no number passed
	if len(args) > 1 {
		if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
			limit = v
		} else {
			utils.SendPlain(bot, update.Message.Chat.ID, "❌ Invalid number provided. Usage: /hist <job-id> [n]")
			return
		}
	}

	// Fetch history for the specific job
	hresp, err := client.Call("GET", "/api/jobs/"+jobID+"/history", nil)
	if err != nil {
		utils.SendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to fetch history for job '%s'.", jobID), err)
		return
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		utils.SendApiError(bot, update.Message.Chat.ID, fmt.Sprintf("API returned an error while fetching history for job '%s'.", jobID), hresp)
		return
	}

	var hist []models.JobExecution
	if err := json.NewDecoder(hresp.Body).Decode(&hist); err != nil {
		utils.SendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to parse history for job '%s'.", jobID), err)
		return
	}

	if len(hist) == 0 {
		utils.SendPlain(bot, update.Message.Chat.ID, fmt.Sprintf("✅ No execution history available for job '%s'.", jobID))
		return
	}

	// API returns most-recent-first already; ensure order and trim to limit
	sort.Slice(hist, func(i, j int) bool { return hist[i].StartTime > hist[j].StartTime })
	if len(hist) > limit {
		hist = hist[:limit]
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("📜 **Last %d Executions for %s**\n\n", len(hist), utils.EscapeMarkdown(jobID)))
	for _, e := range hist {
		start := time.Unix(0, e.StartTime*int64(time.Millisecond)).Format("Jan 2 2006 15:04:05 MST")
		out := strings.ReplaceAll(e.Output, "\n", " ")
		if len(out) > 300 {
			out = out[:300] + "..."
		}
		b.WriteString(fmt.Sprintf("• `%s` — %s\n  Started: %s — Duration: %dms — Exit: %d\n  Output: %s\n\n",
			utils.EscapeMarkdown(e.ID), utils.EscapeMarkdown(e.Status), start, e.Duration, e.ExitCode, utils.EscapeMarkdown(out)))
	}

	msg := tgbotapi.NewMessage(update.Message.Chat.ID, b.String())
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}
