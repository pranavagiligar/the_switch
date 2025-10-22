package main

import (
	"bufio" // NEW: Required for reading the .env file line by line
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// --- Configuration and State ---

var (
	// Global client to make requests to the Job Manager API (main.go)
	httpClient = &http.Client{Timeout: 10 * time.Second}

	// State management for the JWT token
	jwtToken   string
	tokenMutex sync.RWMutex

	// Configuration variables set from environment
	apiBaseURL       string
	defaultUsername  string
	defaultPassword  string
	authorizedUserID int64 // Stores the single authorized Telegram user ID
)

// --- Data Structures for API Communication ---

// AuthResponse matches the login handler response in main.go
type AuthResponse struct {
	Token string `json:"token"`
}

// Job matches the Job structure in main.go, but only contains fields needed for display
type Job struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	CronExpression string `json:"cronExpression"`
	SkipCount      int    `json:"skipCount"`
	NextRunAt      int64  `json:"nextRunAt"`
}

// SkipResponse matches the skip handler response in main.go
type SkipResponse struct {
	ID        string `json:"id"`
	SkipCount int    `json:"skipCount"`
}

// --- Utility Functions ---

// loadEnvFromFile manually reads a .env file and sets environment variables using only standard library functions.
func loadEnvFromFile(filename string) error {
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		// Log a warning and proceed if .env is missing, allowing fallback to system environment
		log.Printf("Warning: .env file not found at %s. Proceeding with system environment variables.", filename)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore comments and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// Split line into key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			// Trim spaces and basic quotes (") from the value
			value := strings.TrimSpace(strings.Trim(parts[1], `"`))
			if key != "" {
				os.Setenv(key, value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading %s: %w", filename, err)
	}
	log.Printf("Successfully loaded configuration from %s.", filename)
	return nil
}

// getJobManagerToken authenticates with the Job Manager API and stores the JWT.
func getJobManagerToken() error {
	log.Println("[AUTH] Attempting to log in to Job Manager API...")

	// 1. Prepare login data
	loginData := map[string]string{
		"username": defaultUsername,
		"password": defaultPassword,
	}
	jsonBody, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("failed to marshal login data: %w", err)
	}

	// 2. Make the POST request to /login
	url := fmt.Sprintf("%s/login", apiBaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API connection error: check if Job Manager is running at %s: %w", apiBaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// 3. Decode the response
	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	// 4. Store the token securely
	tokenMutex.Lock()
	jwtToken = authResponse.Token
	tokenMutex.Unlock()

	log.Println("[AUTH] Successfully authenticated. JWT token acquired.")
	return nil
}

// getJobs fetches the list of jobs from the Job Manager API.
func getJobs() ([]Job, error) {
	tokenMutex.RLock()
	token := jwtToken
	tokenMutex.RUnlock()

	if token == "" {
		return nil, errors.New("not authenticated. Please ensure the bot started successfully with credentials")
	}

	url := fmt.Sprintf("%s/api/jobs", apiBaseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch jobs: API responded with status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var jobs []Job
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return nil, fmt.Errorf("failed to decode jobs response: %w", err)
	}
	return jobs, nil
}

// skipJob sends a request to skip the next execution of a specific job.
func skipJob(jobID string) (SkipResponse, error) {
	tokenMutex.RLock()
	token := jwtToken
	tokenMutex.RUnlock()

	if token == "" {
		return SkipResponse{}, errors.New("not authenticated")
	}

	url := fmt.Sprintf("%s/api/jobs/%s/skip", apiBaseURL, jobID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return SkipResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return SkipResponse{}, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return SkipResponse{}, fmt.Errorf("failed to skip job: API responded with status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var skipRes SkipResponse
	if err := json.NewDecoder(resp.Body).Decode(&skipRes); err != nil {
		return SkipResponse{}, fmt.Errorf("failed to decode skip response: %w", err)
	}
	return skipRes, nil
}

// isAuthorized checks if the given chat ID matches the configured authorizedUserID.
func isAuthorized(chatID int64) bool {
	return chatID == authorizedUserID
}

// --- Telegram Handlers ---

func handleStart(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	msg := tgbotapi.NewMessage(update.Message.Chat.ID,
		"✅ **Access Granted**\n\n"+
			"Welcome to the **Job Manager Bot**! Your ID is authorized.\n"+
			"Use the commands below to manage your scheduled tasks remotely:\n\n"+
			"**/list** - Show all scheduled jobs, cron expressions, and next run times.\n"+
			"**/skip <job-id>** - Skip the next execution for the specified job (e.g., `/skip job-1`).",
	)
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending start message: %v", err)
	}
}

func handleList(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	jobs, err := getJobs()

	if err != nil {
		errMsg := fmt.Sprintf("❌ Error listing jobs: %v", err)
		log.Println(errMsg)
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, errMsg)
		bot.Send(msg)
		return
	}

	if len(jobs) == 0 {
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, "No jobs are currently scheduled in the Job Manager.")
		bot.Send(msg)
		return
	}

	var sb strings.Builder
	sb.WriteString("🗓️ **Scheduled Jobs**:\n\n")

	for _, job := range jobs {
		nextRunTime := "N/A (Invalid Cron)"
		if job.NextRunAt > 0 {
			t := time.Unix(job.NextRunAt/1000, (job.NextRunAt%1000)*int64(time.Millisecond))
			nextRunTime = t.Format("2 Jan 15:04:05")
		}

		sb.WriteString(fmt.Sprintf(
			"**%s** (`%s`)\n"+
				"**ID**: %s\n"+
				"**Cron**: `%s`\n"+
				"**Next Run**: %s\n"+
				"**Skip Count**: %d\n\n",
			job.Title, job.ID, job.ID, job.CronExpression, nextRunTime, job.SkipCount,
		))
	}

	msg := tgbotapi.NewMessage(update.Message.Chat.ID, sb.String())
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending list message: %v", err)
	}
}

func handleSkip(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	// Expecting: /skip job-1
	args := update.Message.CommandArguments()
	parts := strings.Fields(args)

	if len(parts) != 1 {
		msg := tgbotapi.NewMessage(update.Message.Chat.ID,
			"⚠️ Invalid command format. Usage: `/skip <job-id>` (e.g., `/skip job-1`)",
		)
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	jobID := parts[0]

	// Basic validation of job-ID format
	if !strings.HasPrefix(jobID, "job-") {
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Job ID must be in the format `job-N` (e.g., `job-5`).")
		bot.Send(msg)
		return
	}

	// Call the API to skip the job
	skipRes, err := skipJob(jobID)

	if err != nil {
		errMsg := fmt.Sprintf("❌ Error skipping job `%s`: %v", jobID, err)
		log.Println(errMsg)
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, errMsg)
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	successMsg := fmt.Sprintf(
		"✅ Success! Job `%s` was skipped.\n"+
			"The next execution will be ignored.\n"+
			"New Skip Count: %d",
		skipRes.ID, skipRes.SkipCount,
	)

	msg := tgbotapi.NewMessage(update.Message.Chat.ID, successMsg)
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending skip message: %v", err)
	}
}

// --- Main Execution ---

func main() {
	// 0. Load variables from .env file
	// This will read and set variables from the .env file, allowing os.Getenv below to retrieve them.
	if err := loadEnvFromFile(".env"); err != nil {
		log.Fatalf("FATAL: Error loading .env file: %v", err)
	}

	// 1. Load Configuration
	apiBaseURL = os.Getenv("API_BASE_URL")
	botToken := os.Getenv("BOT_TOKEN")
	defaultUsername = os.Getenv("DEFAULT_USERNAME")
	defaultPassword = os.Getenv("DEFAULT_PASSWORD")
	authorizedUserIDStr := os.Getenv("TELEGRAM_USER_ID") // Load Telegram User ID

	// Check if all necessary environment variables are set
	if botToken == "" || apiBaseURL == "" || defaultUsername == "" || defaultPassword == "" || authorizedUserIDStr == "" {
		log.Fatal("FATAL: Missing configuration variables. Please ensure BOT_TOKEN, API_BASE_URL, DEFAULT_USERNAME, DEFAULT_PASSWORD, AND TELEGRAM_USER_ID are set in your .env file or environment.")
	}

	// Parse the authorized user ID
	var err error
	authorizedUserID, err = strconv.ParseInt(authorizedUserIDStr, 10, 64)
	if err != nil {
		log.Fatalf("FATAL: Invalid TELEGRAM_USER_ID: %v. Must be an integer.", err)
	}

	// 2. Initial API Authentication
	if err := getJobManagerToken(); err != nil {
		log.Fatalf("FATAL: Failed initial authentication with Job Manager API: %v", err)
	}

	// 3. Initialize Telegram Bot
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatalf("FATAL: Failed to connect to Telegram API: %v", err)
	}

	bot.Debug = false // Set to true to see API traffic
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// 4. Start listening for updates
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil { // ignore any non-message updates
			continue
		}

		// Authorization Check before processing any commands
		if !isAuthorized(update.Message.Chat.ID) {
			errMsg := fmt.Sprintf(
				"❌ **Unauthorized Access**\n\n"+
					"Your Telegram User ID is not authorized to use this bot. "+
					"If you are the administrator, configure the `TELEGRAM_USER_ID` environment variable in your .env file to match your ID: `%d`",
				update.Message.Chat.ID,
			)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, errMsg)
			msg.ParseMode = "Markdown"
			bot.Send(msg)
			continue // Skip processing any further commands from this unauthorized user
		}

		if !update.Message.IsCommand() { // ignore any non-command messages
			continue
		}

		switch update.Message.Command() {
		case "start":
			handleStart(bot, update)
		case "list":
			handleList(bot, update)
		case "skip":
			handleSkip(bot, update)
		default:
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unknown command. Use /list or /skip.")
			bot.Send(msg)
		}
	}
}
