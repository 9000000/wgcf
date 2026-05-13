package bot

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	. "github.com/ViRb3/wgcf/v2/cmd/shared"
	"github.com/ViRb3/wgcf/v2/config"
	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/cockroachdb/errors"
	"github.com/dustin/go-humanize"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	tgToken        string
	allowedChatIds string
	allowedChatMap map[int64]bool
	botRegLimit    int
	mu             sync.Mutex // Mutex to serialize wgcf operations due to single viper config file
)

var Cmd = &cobra.Command{
	Use:   "bot",
	Short: "Starts a Telegram Bot to manage Cloudflare Warp",
	Long:  FormatMessage("Starts a Telegram Bot to manage Cloudflare Warp", `Allows registering, updating license, viewing status, generating profiles, and tracing through Telegram.`),
	Run: func(cmd *cobra.Command, args []string) {
		if err := startBot(); err != nil {
			log.Fatalf("Bot error: %+v\n", err)
		}
	},
}

func init() {
	Cmd.PersistentFlags().StringVar(&tgToken, "token", "", "Telegram Bot Token (can also be set via WGCF_TELEGRAM_TOKEN env var)")
	Cmd.PersistentFlags().StringVar(&allowedChatIds, "allowed-chat-ids", "", "Comma separated Telegram Chat IDs allowed to use the bot")
	Cmd.PersistentFlags().IntVar(&botRegLimit, "reg-limit", 0, "Successful registration limit per rolling 7 days per user")
}

func startBot() error {
	// Read from environment if not set via flag
	if tgToken == "" {
		tgToken = viper.GetString("telegram_token")
	}
	if allowedChatIds == "" {
		allowedChatIds = viper.GetString("allowed_chat_ids")
	}
	if botRegLimit <= 0 {
		botRegLimit = viper.GetInt("bot_reg_limit")
	}
	if botRegLimit <= 0 {
		botRegLimit = 2 // Default limit
	}

	// Asynchronously initialize and periodically refresh the rotating proxy pool every 2 hours
	go func() {
		// Fetch immediately on boot
		if err := cloudflare.GlobalProxyManager.LoadProxies(); err != nil {
			log.Printf("ProxyManager WARNING: Could not retrieve proxy pool: %v. Will fallback to direct connections.", err)
		}

		ticker := time.NewTicker(2 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			log.Println("ProxyManager: Periodically refreshing latest proxy pool from GitHub source...")
			if err := cloudflare.GlobalProxyManager.LoadProxies(); err != nil {
				log.Printf("ProxyManager WARNING: Period refresh failed: %v. Retaining previous pool state.", err)
			}
		}
	}()

	if tgToken == "" {
		return errors.New("Telegram Token is required. Set --token flag or WGCF_TELEGRAM_TOKEN environment variable")
	}

	// Parse allowed chat IDs
	allowedChatMap = make(map[int64]bool)
	if allowedChatIds != "" {
		ids := strings.Split(allowedChatIds, ",")
		for _, idStr := range ids {
			idStr = strings.TrimSpace(idStr)
			if idStr == "" {
				continue
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				log.Printf("Warning: failed to parse allowed chat ID '%s': %v", idStr, err)
				continue
			}
			allowedChatMap[id] = true
		}
	}

	bot, err := tgbotapi.NewBotAPI(tgToken)
	if err != nil {
		return errors.WithStack(err)
	}

	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		// Check authorization
		if !isUserAuthorized(bot, update.Message) {
			log.Printf("Unauthorized access attempt from chat ID %d (User ID: %d)", update.Message.Chat.ID, update.Message.From.ID)
			continue
		}

		go handleMessage(bot, update.Message)
	}

	return nil
}

func handleMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message) {
	if !msg.IsCommand() {
		return
	}

	// Acquire mutex lock to prevent concurrent access to viper config or cloudflare calls
	mu.Lock()
	defer mu.Unlock()

	// Load individual user configuration based on sender ID
	if err := loadUserConfig(msg.From.ID); err != nil {
		log.Printf("Error loading configuration for user %d: %+v", msg.From.ID, err)
		reply := tgbotapi.NewMessage(msg.Chat.ID, "❌ *Internal Error:* Failed to load user workspace.")
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
		return
	}

	cmd := msg.Command()
	args := msg.CommandArguments()

	var text string
	var err error
	isGroup := msg.Chat.Type != "private"
	targetChatId := msg.From.ID // Send output to user's direct message (DM) to preserve privacy

	log.Printf("[%s] Received command: /%s %s", msg.From.UserName, cmd, args)

	switch cmd {
	case "start", "help":
		text = "*Cloudflare Warp Controller Bot*\n\n" +
			"Available commands:\n" +
			"• `/register` - Create your separate Cloudflare Warp account\n" +
			"• `/status` - Show your Warp account and devices status\n" +
			"• `/generate` - Generate and send your WireGuard configuration\n" +
			"• `/update <license_key>` - Link Warp+ premium license key\n" +
			"• `/reset` - Reset/Delete your current configuration\n" +
			"• `/help` - Show this message\n\n" +
			"💡 *Note:* Responses with account/profile info will be sent directly to your DMs for security."

		// Allow /help in group so people can see commands, but otherwise prefer DM
		if isGroup {
			targetChatId = msg.Chat.ID
		}

	case "register":
		// Enforce direct connection baseline at the start of the operation
		cloudflare.GlobalProxyManager.SetEnabled(false)
		// Guarantee proxy is switched back OFF when this command processing concludes
		defer cloudflare.GlobalProxyManager.SetEnabled(false)

		allowed, limitErr := checkRegLimit(msg.From.ID)
		if limitErr != nil {
			err = limitErr
		} else if !allowed {
			text = fmt.Sprintf("⚠️ *Giới hạn:* Bạn đã đạt mức tối đa đăng ký **%d lần thành công / 7 ngày**. Vui lòng quay lại thử lại sau!", botRegLimit)
		} else {
			text, err = handleRegister()
			if err == nil {
				_ = incrementRegLimit(msg.From.ID)
				// Only increment proxy lifecycle counter if a proxy was actively engaged
				if cloudflare.GlobalProxyManager.IsEnabled() {
					cloudflare.GlobalProxyManager.IncrementUse()
				}
			}
		}
	case "reset":
		text, err = handleReset(msg.From.ID)
	case "status":
		text, err = handleStatus()
	case "update":
		text, err = handleUpdate(args)

	case "generate":
		handleGenerate(bot, msg)
		return
	default:
		text = "Unknown command. Use /help for instructions."
		if isGroup {
			targetChatId = msg.Chat.ID
		}
	}

	if err != nil {
		log.Printf("Command error: %+v", err)
		text = fmt.Sprintf("❌ *Error:*\n```\n%s\n```", err.Error())
		// Show error in source chat
		targetChatId = msg.Chat.ID
	}

	reply := tgbotapi.NewMessage(targetChatId, text)
	reply.ParseMode = tgbotapi.ModeMarkdown
	_, sendErr := bot.Send(reply)

	// If sending to DM failed (e.g., user hasn't started bot)
	if sendErr != nil && isGroup && targetChatId == msg.From.ID {
		log.Printf("Failed to DM user %d: %v", msg.From.ID, sendErr)
		errorMsg := fmt.Sprintf("⚠️ @%s, I cannot send you Direct Messages. Please start a private chat with me first by clicking here: [Start Bot](https://t.me/%s) and try again.", msg.From.UserName, bot.Self.UserName)
		groupReply := tgbotapi.NewMessage(msg.Chat.ID, errorMsg)
		groupReply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(groupReply)
	} else if sendErr == nil && isGroup && targetChatId == msg.From.ID {
		// Notify in group that the command was executed privately
		groupReply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("📩 @%s, I have sent the response to your Direct Messages!", msg.From.UserName))
		bot.Send(groupReply)
	}
}

func handleRegister() (string, error) {
	if err := EnsureNoExistingAccount(); err != nil {
		return "", errors.New("An account is already registered. Use /status to check.")
	}

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		return "", errors.WithStack(err)
	}

	device, err := cloudflare.Register(privateKey.Public(), "PC")
	if err != nil {
		return "", errors.WithStack(err)
	}

	viper.Set(config.PrivateKey, privateKey.String())
	viper.Set(config.DeviceId, device.Id)
	viper.Set(config.AccessToken, device.Token)
	viper.Set(config.LicenseKey, device.Account.License)
	if err := viper.WriteConfig(); err != nil {
		return "", errors.WithStack(err)
	}

	ctx := CreateContext()
	_, err = SetDeviceName(ctx, "TelegramBot")
	if err != nil {
		// Log and proceed, name might not be critical
		log.Printf("Warning: could not set device name: %v", err)
	}

	account, err := cloudflare.GetAccount(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	boundDevices, err := cloudflare.GetBoundDevices(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("✅ *Successfully registered!*\n\n%s", formatAccountDetails(account, boundDevices)), nil
}

func handleStatus() (string, error) {
	if err := EnsureConfigValidAccount(); err != nil {
		return "", errors.New("No registered account found. Run /register first.")
	}

	ctx := CreateContext()
	account, err := cloudflare.GetAccount(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	boundDevices, err := cloudflare.GetBoundDevices(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return formatAccountDetails(account, boundDevices), nil
}

func handleUpdate(args string) (string, error) {
	if err := EnsureConfigValidAccount(); err != nil {
		return "", errors.New("No registered account found. Run /register first.")
	}

	licenseKey := strings.TrimSpace(args)
	if licenseKey == "" {
		return "", errors.New("Please provide the new license key: `/update <LICENSE_KEY>`")
	}

	ctx := CreateContext()
	ctx.LicenseKey = licenseKey

	account, err := cloudflare.GetAccount(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if account.License != ctx.LicenseKey {
		if _, err := cloudflare.UpdateLicenseKey(ctx); err != nil {
			return "", errors.WithStack(err)
		}
		viper.Set(config.LicenseKey, ctx.LicenseKey)
		if err := viper.WriteConfig(); err != nil {
			return "", errors.WithStack(err)
		}
	}

	// Refresh stats
	account, err = cloudflare.GetAccount(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	boundDevices, err := cloudflare.GetBoundDevices(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("✅ *Successfully updated license!*\n\n%s", formatAccountDetails(account, boundDevices)), nil
}

func handleTrace() (string, error) {
	response, err := http.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("🌐 *Trace Result:*\n```\n%s\n```", strings.TrimSpace(string(bodyBytes))), nil
}

func handleGenerate(bot *tgbotapi.BotAPI, msg *tgbotapi.Message) {
	isGroup := msg.Chat.Type != "private"
	targetChatId := msg.From.ID // Send to DM for privacy

	if err := EnsureConfigValidAccount(); err != nil {
		reply := tgbotapi.NewMessage(msg.Chat.ID, "❌ *Error:* No registered account found. Run /register first.")
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
		return
	}

	ctx := CreateContext()
	thisDevice, err := cloudflare.GetSourceDevice(ctx)
	if err != nil {
		reply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("❌ *Error getting device:* `%v`", err))
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
		return
	}

	profile, err := wireguard.NewProfile(&wireguard.ProfileData{
		PrivateKey: viper.GetString(config.PrivateKey),
		Address1:   thisDevice.Config.Interface.Addresses.V4,
		Address2:   thisDevice.Config.Interface.Addresses.V6,
		PublicKey:  thisDevice.Config.Peers[0].PublicKey,
		Endpoint:   thisDevice.Config.Peers[0].Endpoint.Host,
	})
	if err != nil {
		reply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("❌ *Error constructing profile:* `%v`", err))
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
		return
	}

	profileStr := profile.String()
	fileBytes := tgbotapi.FileBytes{
		Name:  "wgcf-profile.conf",
		Bytes: []byte(profileStr),
	}

	docMsg := tgbotapi.NewDocument(targetChatId, fileBytes)
	docMsg.Caption = "🔒 *Here is your private WireGuard configuration profile!*"
	docMsg.ParseMode = tgbotapi.ModeMarkdown

	_, sendErr := bot.Send(docMsg)
	if sendErr != nil {
		log.Printf("Failed to send document to user %d: %+v", msg.From.ID, sendErr)

		if isGroup {
			errorMsg := fmt.Sprintf("⚠️ @%s, I couldn't send your config privately. Please start a private chat with me first by clicking here: [Start Bot](https://t.me/%s) and try again.", msg.From.UserName, bot.Self.UserName)
			groupReply := tgbotapi.NewMessage(msg.Chat.ID, errorMsg)
			groupReply.ParseMode = tgbotapi.ModeMarkdown
			bot.Send(groupReply)
		} else {
			// Fallback in private chat if document fails, just send text
			reply := tgbotapi.NewMessage(targetChatId, fmt.Sprintf("📁 *Profile config content:*\n```\n%s\n```", profileStr))
			reply.ParseMode = tgbotapi.ModeMarkdown
			bot.Send(reply)
		}
	} else if isGroup {
		// Success notification in group
		groupReply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("📩 @%s, I have sent your WireGuard profile directly to your Private Messages!", msg.From.UserName))
		bot.Send(groupReply)
	}
}

func formatAccountDetails(account *cloudflare.Account, boundDevices []cloudflare.BoundDevice) string {
	var sb strings.Builder

	sb.WriteString("👤 *Account Status:*\n")
	sb.WriteString(fmt.Sprintf("• ID: `%s`\n", account.Id))
	sb.WriteString(fmt.Sprintf("• Type: *%s*\n", account.AccountType))
	sb.WriteString(fmt.Sprintf("• Quota: `%s`\n", humanize.Bytes(uint64(account.Quota))))
	sb.WriteString(fmt.Sprintf("• Premium Data: `%s`\n", humanize.Bytes(uint64(account.PremiumData))))
	sb.WriteString(fmt.Sprintf("• Role: `%s`\n", account.Role))
	sb.WriteString("\n📱 *Devices linked:*")

	for i, device := range boundDevices {
		name := "N/A"
		if device.Name != nil {
			name = *device.Name
		}
		current := ""
		if device.Id == viper.GetString(config.DeviceId) {
			current = " *(Current)*"
		}

		statusEmoji := "⚪️"
		if device.Active {
			statusEmoji = "🟢"
		}

		sb.WriteString(fmt.Sprintf("\n%d. %s %s `%s`%s", i+1, statusEmoji, name, device.Id, current))
		sb.WriteString(fmt.Sprintf("\n   • Model: %s (%s)", device.Model, device.Type))
	}

	return sb.String()
}

func loadUserConfig(userId int64) error {
	userDir := filepath.Join("users", strconv.FormatInt(userId, 10))
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return errors.WithStack(err)
	}

	configFile := filepath.Join(userDir, "wgcf-account.toml")

	// Ensure config file exists so viper doesn't fail
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		f, err := os.Create(configFile)
		if err != nil {
			return errors.WithStack(err)
		}
		f.Close()
	}

	// Reset and re-load settings into global viper for the scope of this lock execution
	viper.Reset()
	viper.SetDefault(config.DeviceId, "")
	viper.SetDefault(config.AccessToken, "")
	viper.SetDefault(config.PrivateKey, "")
	viper.SetDefault(config.LicenseKey, "")

	viper.SetConfigFile(configFile)
	viper.SetEnvPrefix("WGCF")
	viper.AutomaticEnv()

	// Read the user's configuration
	_ = viper.ReadInConfig()

	return nil
}

func isUserAuthorized(bot *tgbotapi.BotAPI, msg *tgbotapi.Message) bool {
	if len(allowedChatMap) == 0 {
		return true
	}

	// 1. Direct match: Sent directly from an authorized Group or by an authorized User Chat ID
	if allowedChatMap[msg.Chat.ID] {
		return true
	}

	// 2. Explicit Sender match: Sender's User ID is explicitly in allowedChatMap
	if allowedChatMap[msg.From.ID] {
		return true
	}

	// 3. Group membership check: If message is from a private chat, check if user belongs to ANY authorized group
	if msg.Chat.Type == "private" {
		for chatId := range allowedChatMap {
			// Group IDs are negative in Telegram
			if chatId < 0 {
				config := tgbotapi.GetChatMemberConfig{
					ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
						ChatID: chatId,
						UserID: msg.From.ID,
					},
				}
				member, err := bot.GetChatMember(config)
				if err != nil {
					log.Printf("Debug: GetChatMember error for User %d in Group %d: %v", msg.From.ID, chatId, err)
				} else {
					status := member.Status
					if status == "creator" || status == "administrator" || status == "member" {
						return true
					}
				}
			}
		}
	}

	return false
}

func handleReset(userId int64) (string, error) {
	userDir := filepath.Join("users", strconv.FormatInt(userId, 10))
	configFile := filepath.Join(userDir, "wgcf-account.toml")

	// Check if file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return "ℹ️ You do not have an existing configuration to reset.", nil
	}

	// Delete the configuration file
	if err := os.Remove(configFile); err != nil {
		return "", errors.Wrap(err, "failed to delete configuration file")
	}

	// Force reset of global viper session immediately
	viper.Reset()
	viper.SetDefault(config.DeviceId, "")
	viper.SetDefault(config.AccessToken, "")
	viper.SetDefault(config.PrivateKey, "")
	viper.SetDefault(config.LicenseKey, "")

	log.Printf("User %d reset their configuration", userId)
	return "✅ *Successfully reset!* Your local configuration has been completely deleted. You can now use `/register` to start over.", nil
}

type RegLimit struct {
	Timestamps []int64 `json:"timestamps"`
}

func checkRegLimit(userId int64) (bool, error) {
	userDir := filepath.Join("users", strconv.FormatInt(userId, 10))
	limitFile := filepath.Join(userDir, "reg_limit.json")

	if _, err := os.Stat(limitFile); os.IsNotExist(err) {
		return true, nil
	}

	data, err := os.ReadFile(limitFile)
	if err != nil {
		return false, errors.WithStack(err)
	}

	var limit RegLimit
	if err := json.Unmarshal(data, &limit); err != nil {
		limit = RegLimit{}
	}

	now := time.Now().Unix()
	sevenDaysInSecs := int64(7 * 24 * 60 * 60)
	cutoff := now - sevenDaysInSecs

	validCount := 0
	for _, ts := range limit.Timestamps {
		if ts > cutoff {
			validCount++
		}
	}

	if validCount >= botRegLimit {
		return false, nil
	}

	return true, nil
}

func incrementRegLimit(userId int64) error {
	userDir := filepath.Join("users", strconv.FormatInt(userId, 10))
	limitFile := filepath.Join(userDir, "reg_limit.json")

	if err := os.MkdirAll(userDir, 0755); err != nil {
		return errors.WithStack(err)
	}

	var limit RegLimit
	if data, err := os.ReadFile(limitFile); err == nil {
		_ = json.Unmarshal(data, &limit)
	}

	now := time.Now().Unix()
	sevenDaysInSecs := int64(7 * 24 * 60 * 60)
	cutoff := now - sevenDaysInSecs

	var newTimestamps []int64
	for _, ts := range limit.Timestamps {
		if ts > cutoff {
			newTimestamps = append(newTimestamps, ts)
		}
	}
	newTimestamps = append(newTimestamps, now)
	limit.Timestamps = newTimestamps

	data, err := json.MarshalIndent(limit, "", "  ")
	if err != nil {
		return errors.WithStack(err)
	}

	if err := os.WriteFile(limitFile, data, 0644); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

