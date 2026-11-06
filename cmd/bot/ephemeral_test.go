package bot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func TestRawIncomingUpdatePreservesEphemeralCommandMetadata(t *testing.T) {
	const payload = `{
		"update_id": 9,
		"message": {
			"message_id": 0,
			"from": {"id": 42, "is_bot": false, "first_name": "User"},
			"receiver_user": {"id": 99, "is_bot": true, "first_name": "Bot"},
			"ephemeral_message_id": 777,
			"message_thread_id": 17,
			"chat": {"id": -100123, "type": "supergroup"},
			"text": "/help",
			"entities": [{"type": "bot_command", "offset": 0, "length": 5}]
		}
	}`

	var raw rawIncomingUpdate
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		t.Fatal(err)
	}
	update, ref := raw.toUpdate()
	if update.UpdateID != 9 || update.Message == nil || update.Message.MessageID != 0 {
		t.Fatalf("unexpected converted update: %+v", update)
	}
	if ref == nil || ref.ChatID != -100123 || ref.ReceiverID != 99 || ref.MessageID != 777 || ref.ThreadID != 17 {
		t.Fatalf("unexpected ephemeral metadata: %+v", ref)
	}
}

func TestBuildEphemeralCommands(t *testing.T) {
	commands := buildEphemeralCommands([]tgbotapi.BotCommand{
		{Command: "help", Description: "Help"},
	})
	data, err := json.Marshal(commands)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0]["is_ephemeral"] != true {
		t.Fatalf("expected group command to be ephemeral: %s", data)
	}
}

func TestFormatAccountDetailsEscapesHTML(t *testing.T) {
	name := "device_<&>"
	model := "model_<&>"
	account := &cloudflare.Account{
		Id:          "id_<&>",
		AccountType: "type_<&>",
		Role:        "role_<&>",
	}
	devices := []cloudflare.BoundDevice{{
		Id:    "device-id_<&>",
		Name:  &name,
		Model: &model,
		Type:  "type_<&>",
	}}

	got := formatAccountDetails(account, devices)
	for _, want := range []string{
		"id_&lt;&amp;&gt;",
		"type_&lt;&amp;&gt;",
		"role_&lt;&amp;&gt;",
		"device_&lt;&amp;&gt;",
		"model_&lt;&amp;&gt;",
		"device-id_&lt;&amp;&gt;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("formatAccountDetails() missing escaped value %q in %q", want, got)
		}
	}
}
