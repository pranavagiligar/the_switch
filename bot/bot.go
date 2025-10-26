package main

import (
	"bufio" // NEW: Required for reading the .env file line by line
	"bytes"
	"encoding/json"
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

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
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
	Message   string `json:"message"`
}

// --- Utility Functions ---

// loadEnv loads environment variables from a .env file
func loadEnv(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("[INFO] .env file not found or could not be opened: %v. Using OS environment variables.", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(strings.Trim(parts[1], `"`))
			os.Setenv(key, value)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[WARNING] Error reading .env file: %v", err)
	}
}

// initializeConfig reads configuration from environment variables
func initializeConfig() {
	apiBaseURL = os.Getenv("API_BASE_URL")
	if apiBaseURL == "" {
		// Use the default if environment variable is not set
		apiBaseURL = "http://localhost:8080"
	}

	defaultUsername = os.Getenv("DEFAULT_USERNAME")
	if defaultUsername == "" {
		defaultUsername = "admin"
	}

	defaultPassword = os.Getenv("DEFAULT_PASSWORD")
	if defaultPassword == "" {
		defaultPassword = "password"
	}

	userIDStr := os.Getenv("TELEGRAM_USER_ID")
	if userIDStr == "" {
		log.Printf("[WARNING] TELEGRAM_USER_ID is not set. The bot will not be able to authorize any users.")
	} else {
		id, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			log.Fatalf("FATAL: Invalid TELEGRAM_USER_ID format: %v", err)
		}
		authorizedUserID = id
		log.Printf("[INFO] Bot authorized for Telegram user ID: %d", authorizedUserID)
	}
	log.Printf("[INFO] API Base URL set to: %s", apiBaseURL)
}

// authenticate attempts to get a new JWT token from the API
func authenticate() error {
	log.Println("[AUTH] Attempting to authenticate with Job Manager API...")

	payload := map[string]string{
		"username": defaultUsername,
		"password": defaultPassword,
	}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", apiBaseURL+"/login", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errRes map[string]string
		json.NewDecoder(resp.Body).Decode(&errRes)
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, errRes["error"])
	}

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	tokenMutex.Lock()
	jwtToken = authResponse.Token
	tokenMutex.Unlock()
	log.Println("[AUTH] Successfully authenticated. Token obtained.")
	return nil
}

// refreshAuth ensures the JWT is available and valid (by trying to refresh if needed)
func refreshAuth() error {
	tokenMutex.RLock()
	tokenExists := jwtToken != ""
	tokenMutex.RUnlock()

	if !tokenExists {
		return authenticate()
	}
	// In a real scenario, you'd check token expiration here. For simplicity,
	// we rely on the API returning 401 and triggering a re-auth on the next API call.
	return nil
}

// isAuthorized checks if the Telegram chat ID matches the authorized user ID
func isAuthorized(chatID int64) bool {
	return authorizedUserID != 0 && chatID == authorizedUserID
}

// apiCall performs an authenticated call to the job manager API
func apiCall(method, path string, body io.Reader) (*http.Response, error) {
	// Ensure authentication is fresh
	if err := refreshAuth(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	url := apiBaseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	tokenMutex.RLock()
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	tokenMutex.RUnlock()

	resp, err := httpClient.Do(req)

	// If 401, clear the token and try again once (recursive call, limited depth)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		log.Println("[AUTH] Token expired, attempting re-authentication...")
		tokenMutex.Lock()
		jwtToken = "" // Clear invalid token
		tokenMutex.Unlock()
		if err := authenticate(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		// Second attempt after re-authentication
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		return httpClient.Do(req)
	}

	return resp, err
}

// --- Command Handlers ---

// handleStart sends the welcome message and instructions
func handleStart(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	// A simple helper function to generate the common help text
	helpText := fmt.Sprintf(
		"👋 **Welcome to The Switch Bot!**\n\n"+
			"This bot helps you manage your *Scheduled Job Manager* running at: `%s`\n\n"+
			"### Commands\n"+
			"• /list - List all scheduled jobs.\n"+
			"• /skip <id> - Skip the next scheduled run for a specific job ID.\n"+
			"• /run <id> - Manually trigger a job to run immediately.\n"+
			"• /help - Show this message.\n\n"+
			"Your Telegram ID: `%d`\n",
		apiBaseURL,
		update.Message.Chat.ID,
	)

	msg := tgbotapi.NewMessage(update.Message.Chat.ID, helpText)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

// handleList fetches and displays all scheduled jobs
func handleList(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	resp, err := apiCall("GET", "/api/jobs/", nil)
	if err != nil {
		sendError(bot, update.Message.Chat.ID, "Failed to connect to API or authenticate.", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sendApiError(bot, update.Message.Chat.ID, "API returned an error while fetching jobs.", resp)
		return
	}

	var jobs []Job
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		sendError(bot, update.Message.Chat.ID, "Failed to parse API response for jobs list.", err)
		return
	}

	if len(jobs) == 0 {
		sendPlain(bot, update.Message.Chat.ID, "✅ No jobs are currently scheduled.")
		return
	}

	var message strings.Builder
	message.WriteString("📋 **Scheduled Jobs**\n\n")

	for _, job := range jobs {
		// Convert NextRunAt from Unix milliseconds to readable format
		nextRunTime := time.Unix(0, job.NextRunAt*int64(time.Millisecond)).Format("Jan 2, 2006 15:04:05 MST")
		if job.NextRunAt == 0 {
			nextRunTime = "Invalid CRON"
		}

		message.WriteString(fmt.Sprintf(
			"**ID:** `%s`\n"+
				"**Title:** %s\n"+
				"**Cron:** `%s`\n"+
				"**Next:** %s\n"+
				"**Skips:** %d\n\n",
			job.ID,
			job.Title,
			job.CronExpression,
			nextRunTime,
			job.SkipCount,
		))
	}

	sendMarkdown(bot, update.Message.Chat.ID, message.String())
}

// handleSkip skips the next execution of a specified job
func handleSkip(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	jobID := update.Message.CommandArguments()
	if jobID == "" {
		sendPlain(bot, update.Message.Chat.ID, "❌ Please specify a Job ID. Usage: /skip job-1")
		return
	}

	resp, err := apiCall("POST", "/api/jobs/"+jobID+"/skip", nil)
	if err != nil {
		sendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to connect or authenticate to skip job `%s`.", jobID), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sendApiError(bot, update.Message.Chat.ID, fmt.Sprintf("API returned an error while skipping job `%s`.", jobID), resp)
		return
	}

	var skipRes SkipResponse
	if err := json.NewDecoder(resp.Body).Decode(&skipRes); err != nil {
		sendError(bot, update.Message.Chat.ID, "Failed to parse API response for skip operation.", err)
		return
	}

	msgText := fmt.Sprintf("✅ Job `%s` successfully skipped.\nNew Skip Count: **%d**", jobID, skipRes.SkipCount)
	sendMarkdown(bot, update.Message.Chat.ID, msgText)
}

// handleRun manually triggers a specified job
func handleRun(bot *tgbotapi.BotAPI, update tgbotapi.Update) {
	jobID := update.Message.CommandArguments()
	if jobID == "" {
		sendPlain(bot, update.Message.Chat.ID, "❌ Please specify a Job ID. Usage: /run job-1")
		return
	}

	// NOTE: This uses the new /run endpoint implemented in main.go (Feature 2)
	resp, err := apiCall("POST", "/api/jobs/"+jobID+"/run", nil)
	if err != nil {
		sendError(bot, update.Message.Chat.ID, fmt.Sprintf("Failed to connect or authenticate to run job `%s`.", jobID), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		sendPlain(bot, update.Message.Chat.ID, fmt.Sprintf("⚡ Job `%s` queued for immediate execution! Check the web UI for logs.", jobID))
	} else {
		sendApiError(bot, update.Message.Chat.ID, fmt.Sprintf("API returned an error while trying to run job `%s`.", jobID), resp)
	}
}

// --- Message Sending Functions ---

func sendPlain(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	bot.Send(msg)
}

func sendMarkdown(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func sendError(bot *tgbotapi.BotAPI, chatID int64, context string, err error) {
	log.Printf("[ERROR] %s: %v", context, err)
	errMsg := fmt.Sprintf("❌ **Error:** %s\n\nDetails: `%s`", context, err.Error())
	sendMarkdown(bot, chatID, errMsg)
}

func sendApiError(bot *tgbotapi.BotAPI, chatID int64, context string, resp *http.Response) {
	var errRes map[string]string
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()                                    // Close after reading
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Re-set body for potential re-reading

	if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
		log.Printf("[ERROR] %s - Failed to unmarshal API error response: %v", context, err)
	}

	apiError := errRes["error"]
	if apiError == "" {
		apiError = fmt.Sprintf("Unknown error. Status Code: %d", resp.StatusCode)
	}

	log.Printf("[API ERROR] %s - Status %d: %s", context, resp.StatusCode, apiError)
	errMsg := fmt.Sprintf("❌ **API Failure** (Status: %d)\n\nContext: %s\nDetails: `%s`", resp.StatusCode, context, apiError)
	sendMarkdown(bot, chatID, errMsg)
}

// --- Main Function ---

func main() {
	fmt.Printf("Version: %s, Commit: %s, Built: %s\n", version, commit, buildTime)

	// 1. Load configuration from .env and environment variables
	loadEnv(".env")
	initializeConfig()

	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("FATAL: TELEGRAM_BOT_TOKEN environment variable not set.")
	}

	// 2. Initial Authentication
	if err := authenticate(); err != nil {
		log.Fatalf("FATAL: Initial authentication with Job Manager API: %v", err)
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
		case "start", "help":
			handleStart(bot, update)
		case "list":
			handleList(bot, update)
		case "skip":
			handleSkip(bot, update)
		case "run":
			handleRun(bot, update)
		default:
			sendPlain(bot, update.Message.Chat.ID, "Unknown command. Use /help to see available commands.")
		}
	}
}
