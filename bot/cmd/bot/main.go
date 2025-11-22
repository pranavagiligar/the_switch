package main

import (
	"fmt"
	"log"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/pranavagiligar/the_switch_bot/internal/api"
	"github.com/pranavagiligar/the_switch_bot/internal/config"
	"github.com/pranavagiligar/the_switch_bot/internal/handlers"
	"github.com/pranavagiligar/the_switch_bot/internal/poller"
	"github.com/pranavagiligar/the_switch_bot/internal/utils"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	fmt.Printf("Version: %s, Commit: %s, Built: %s\n", version, commit, buildTime)

	// 1. Load configuration from .env and environment variables
	config.LoadEnv(".env")
	cfg := config.InitializeConfig()

	// 2. Initialize API Client and Authenticate
	client := api.NewClient(cfg)
	if err := client.Authenticate(); err != nil {
		log.Fatalf("FATAL: Initial authentication with Job Manager API: %v", err)
	}

	// 3. Initialize Telegram Bot
	bot, err := tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Fatalf("FATAL: Failed to connect to Telegram API: %v", err)
	}

	bot.Debug = false // Set to true to see API traffic
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// 4. Start listening for updates
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	// Start background pollers
	go poller.PollAndScheduleNotifications(bot, client, cfg) // For pre-run reminders
	go poller.PollJobExecutions(bot, client, cfg)            // For post-execution notifications

	for update := range updates {
		if update.Message == nil { // ignore any non-message updates
			continue
		}

		// Authorization Check before processing any commands
		if cfg.AuthorizedUserID != 0 && update.Message.Chat.ID != cfg.AuthorizedUserID {
			errMsg := fmt.Sprintf(
				"❌ **Unauthorized Access**\n\n"+
					"Your Telegram User ID is not authorized to use this bot. "+
					"Please check the `TELEGRAM_USER_ID` setting in the bot configuration.\n\n"+
					"Your ID: `%d`",
				update.Message.Chat.ID,
			)
			utils.SendMarkdown(bot, update.Message.Chat.ID, errMsg)
			log.Printf("[AUTH] Unauthorized access attempt from ID: %d", update.Message.Chat.ID)
			continue
		}

		// Command Handling
		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "start", "help":
				handlers.HandleStart(bot, update, cfg)
			case "list":
				handlers.HandleList(bot, update, client)
			case "skip":
				handlers.HandleSkip(bot, update, client)
			case "run":
				handlers.HandleRun(bot, update, client)
			case "hist":
				handlers.HandleHist(bot, update, client)
			default:
				utils.SendPlain(bot, update.Message.Chat.ID, "❓ Unknown command. Type /help to see available commands.")
			}
		}
	}
}
