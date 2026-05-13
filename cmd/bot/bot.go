package bot

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

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
	tgToken         string
	allowedChatIds  string
	allowedChatMap  map[int64]bool
	mu              sync.Mutex // Mutex to serialize wgcf operations due to single viper config file
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
}

func startBot() error {
	// Read from environment if not set via flag
	if tgToken == "" {
		tgToken = viper.GetString("telegram_token")
	}
	if allowedChatIds == "" {
		allowedChatIds = viper.GetString("allowed_chat_ids")
	}

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
		if len(allowedChatMap) > 0 {
			if !allowedChatMap[update.Message.Chat.ID] {
				log.Printf("Unauthorized access attempt by chat ID %d", update.Message.Chat.ID)
				continue
			}
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

	cmd := msg.Command()
	args := msg.CommandArguments()

	var text string
	var err error

	log.Printf("[%s] Received command: /%s %s", msg.From.UserName, cmd, args)

	switch cmd {
	case "start", "help":
		text = "*Cloudflare Warp Controller Bot*\n\n" +
			"Available commands:\n" +
			"• `/register` - Create a new Cloudflare Warp account\n" +
			"• `/status` - Show Warp account and devices status\n" +
			"• `/generate` - Generate and send WireGuard configuration\n" +
			"• `/update <license_key>` - Link Warp+ premium license key\n" +
			"• `/trace` - Show Cloudflare Warp diagnostics\n" +
			"• `/help` - Show this message"
		reply := tgbotapi.NewMessage(msg.Chat.ID, text)
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
		return

	case "register":
		text, err = handleRegister()
	case "status":
		text, err = handleStatus()
	case "update":
		text, err = handleUpdate(args)
	case "trace":
		text, err = handleTrace()
	case "generate":
		handleGenerate(bot, msg)
		return
	default:
		text = "Unknown command. Use /help for instructions."
	}

	if err != nil {
		log.Printf("Command error: %+v", err)
		text = fmt.Sprintf("❌ *Error:*\n```\n%s\n```", err.Error())
	}

	reply := tgbotapi.NewMessage(msg.Chat.ID, text)
	reply.ParseMode = tgbotapi.ModeMarkdown
	bot.Send(reply)
}

func handleRegister() (string, error) {
	if err := EnsureNoExistingAccount(); err != nil {
		return "", errors.New("An account is already registered. Use /status to check.")
	}

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		return "", errors.WithStack(err)
	}

	device, err := cloudflare.Register(privateKey.Public(), "TelegramBot")
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

	docMsg := tgbotapi.NewDocument(msg.Chat.ID, fileBytes)
	docMsg.Caption = "🔒 *Here is your WireGuard configuration profile!*"
	docMsg.ParseMode = tgbotapi.ModeMarkdown

	_, err = bot.Send(docMsg)
	if err != nil {
		log.Printf("Failed to send document: %+v", err)
		// Fallback send text
		reply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("📁 *Profile config content:*\n```\n%s\n```", profileStr))
		reply.ParseMode = tgbotapi.ModeMarkdown
		bot.Send(reply)
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
