package config

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	APIBaseURL       string
	DefaultUsername  string
	DefaultPassword  string
	AuthorizedUserID int64
	BotToken         string
}

// LoadEnv loads environment variables from a .env file
func LoadEnv(filename string) {
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

// InitializeConfig reads configuration from environment variables
func InitializeConfig() *Config {
	apiBaseURL := os.Getenv("API_BASE_URL")
	if apiBaseURL == "" {
		apiBaseURL = "http://localhost:8080"
	}

	defaultUsername := os.Getenv("DEFAULT_USERNAME")
	if defaultUsername == "" {
		defaultUsername = "admin"
	}

	defaultPassword := os.Getenv("DEFAULT_PASSWORD")
	if defaultPassword == "" {
		defaultPassword = "password"
	}

	var authorizedUserID int64
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

	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("FATAL: TELEGRAM_BOT_TOKEN environment variable not set.")
	}

	return &Config{
		APIBaseURL:       apiBaseURL,
		DefaultUsername:  defaultUsername,
		DefaultPassword:  defaultPassword,
		AuthorizedUserID: authorizedUserID,
		BotToken:         botToken,
	}
}
