package bot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type incomingEphemeralRef struct {
	ChatID     int64
	ReceiverID int64
	MessageID  int64
	ThreadID   int
}

var incomingEphemeralCommands sync.Map

type rawIncomingMessage struct {
	tgbotapi.Message
	ReceiverUser       *tgbotapi.User `json:"receiver_user,omitempty"`
	EphemeralMessageID int64          `json:"ephemeral_message_id,omitempty"`
	MessageThreadID    int            `json:"message_thread_id,omitempty"`
}

type rawIncomingUpdate struct {
	tgbotapi.Update
	Message *rawIncomingMessage `json:"message,omitempty"`
}

func (raw rawIncomingUpdate) toUpdate() (tgbotapi.Update, *incomingEphemeralRef) {
	update := raw.Update
	if raw.Message == nil {
		return update, nil
	}
	update.Message = &raw.Message.Message
	if raw.Message.EphemeralMessageID == 0 || !raw.Message.IsCommand() || raw.Message.Chat == nil {
		return update, nil
	}

	ref := &incomingEphemeralRef{
		ChatID:    raw.Message.Chat.ID,
		MessageID: raw.Message.EphemeralMessageID,
		ThreadID:  raw.Message.MessageThreadID,
	}
	if raw.Message.ReceiverUser != nil {
		ref.ReceiverID = int64(raw.Message.ReceiverUser.ID)
	}
	return update, ref
}

type rawBotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
	IsEphemeral bool   `json:"is_ephemeral"`
}

func buildEphemeralCommands(commands []tgbotapi.BotCommand) []rawBotCommand {
	raw := make([]rawBotCommand, 0, len(commands))
	for _, command := range commands {
		raw = append(raw, rawBotCommand{
			Command:     command.Command,
			Description: command.Description,
			IsEphemeral: true,
		})
	}
	return raw
}

func telegramJSONRequest(bot *tgbotapi.BotAPI, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("https://api.telegram.org/bot%s/%s", bot.Token, method), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	client := bot.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Telegram API HTTP %d: %s", response.StatusCode, responseBody)
	}

	var result struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("Telegram API: %s", result.Description)
	}
	return result.Result, nil
}

func setGroupCommandsEphemeral(bot *tgbotapi.BotAPI, commands []tgbotapi.BotCommand) error {
	_, err := telegramJSONRequest(bot, "setMyCommands", map[string]any{
		"scope":    map[string]string{"type": "all_group_chats"},
		"commands": buildEphemeralCommands(commands),
	})
	if err == nil {
		return nil
	}

	log.Printf("Warning: failed to set ephemeral group commands: %v; falling back to regular commands", err)
	config := tgbotapi.NewSetMyCommandsWithScope(tgbotapi.NewBotCommandScopeAllGroupChats(), commands...)
	_, fallbackErr := bot.Request(config)
	return fallbackErr
}

func sendEphemeralMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, threadID int, text, parseMode string, ttl time.Duration) error {
	if msg == nil || msg.Chat == nil || msg.From == nil {
		return fmt.Errorf("message chat or sender is missing")
	}

	params := map[string]any{
		"chat_id": msg.Chat.ID,
		"text":    text,
		"ephemeral_message_parameters": map[string]any{
			"receiver_user_id": msg.From.ID,
		},
		"disable_notification": true,
	}
	if parseMode != "" {
		params["parse_mode"] = parseMode
	}
	if threadID != 0 {
		params["message_thread_id"] = threadID
	}

	data, err := telegramJSONRequest(bot, "sendMessage", params)
	if err != nil {
		return err
	}
	var result struct {
		EphemeralMessageID int64 `json:"ephemeral_message_id"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.EphemeralMessageID != 0 && ttl > 0 {
		chatID := msg.Chat.ID
		receiverID := int64(msg.From.ID)
		messageID := result.EphemeralMessageID
		time.AfterFunc(ttl, func() {
			deleteEphemeralMessage(bot, chatID, receiverID, messageID)
		})
	}
	return nil
}

func deleteEphemeralMessage(bot *tgbotapi.BotAPI, chatID, receiverID, messageID int64) {
	if bot == nil || chatID == 0 || receiverID == 0 || messageID == 0 {
		return
	}
	_, err := telegramJSONRequest(bot, "deleteEphemeralMessage", map[string]int64{
		"chat_id":              chatID,
		"receiver_user_id":     receiverID,
		"ephemeral_message_id": messageID,
	})
	if err != nil {
		log.Printf("Ephemeral message deletion failed (chat=%d receiver=%d message=%d): %v",
			chatID, receiverID, messageID, err)
	}
}

func scheduleCommandDeletion(bot *tgbotapi.BotAPI, updateID int, msg *tgbotapi.Message, delay time.Duration) {
	if refValue, ok := incomingEphemeralCommands.LoadAndDelete(updateID); ok {
		ref := refValue.(incomingEphemeralRef)
		if ref.ReceiverID == 0 {
			ref.ReceiverID = int64(bot.Self.ID)
		}
		time.AfterFunc(delay, func() {
			deleteEphemeralMessage(bot, ref.ChatID, ref.ReceiverID, ref.MessageID)
		})
		return
	}
	if msg != nil && msg.Chat != nil && msg.MessageID > 0 {
		scheduleDeletionAfter(bot, msg.Chat.ID, msg.MessageID, delay)
	}
}

func scheduleDeletionAfter(bot *tgbotapi.BotAPI, chatID int64, messageID int, delay time.Duration) {
	time.AfterFunc(delay, func() {
		_, err := bot.Request(tgbotapi.NewDeleteMessage(chatID, messageID))
		if err != nil {
			log.Printf("Message deletion failed (chat=%d message=%d): %v", chatID, messageID, err)
		}
	})
}

func sendGroupCommandReply(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, threadID int, text, parseMode string, ttl time.Duration) error {
	if msg == nil || msg.Chat == nil {
		return fmt.Errorf("message chat is missing")
	}
	if err := sendEphemeralMessage(bot, msg, threadID, text, parseMode, ttl); err == nil {
		return nil
	} else {
		log.Printf("Ephemeral group reply failed (chat=%d): %v; falling back to a temporary public message", msg.Chat.ID, err)
	}

	params := map[string]any{
		"chat_id":              msg.Chat.ID,
		"text":                 text,
		"disable_notification": true,
	}
	if parseMode != "" {
		params["parse_mode"] = parseMode
	}
	if threadID != 0 {
		params["message_thread_id"] = threadID
	}
	data, err := telegramJSONRequest(bot, "sendMessage", params)
	if err != nil {
		return err
	}
	var result struct {
		MessageID int `json:"message_id"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.MessageID > 0 {
		scheduleDeletionAfter(bot, msg.Chat.ID, result.MessageID, 3*time.Second)
	}
	return nil
}
