package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// EscapeMarkdown escapes Markdown special characters in a string
func EscapeMarkdown(s string) string {
	specialChars := []string{"_", "*", "`", "["}
	escaped := s
	for _, char := range specialChars {
		escaped = strings.ReplaceAll(escaped, char, "\\"+char)
	}
	return escaped
}

func SendPlain(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	bot.Send(msg)
}

func SendMarkdown(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func SendError(bot *tgbotapi.BotAPI, chatID int64, context string, err error) {
	log.Printf("[ERROR] %s: %v", context, err)
	errMsg := fmt.Sprintf("❌ **Error:** %s\n\nDetails: `%s`", context, err.Error())
	SendMarkdown(bot, chatID, errMsg)
}

func SendApiError(bot *tgbotapi.BotAPI, chatID int64, context string, resp *http.Response) {
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
	SendMarkdown(bot, chatID, errMsg)
}
