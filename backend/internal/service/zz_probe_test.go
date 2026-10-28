package service

import "testing"

func TestIsClaudeCodeClientProbe(t *testing.T) {
	uid := `{"device_id":"5215212ecec002d8e20d962940b7be8b70aa2564f58e2346832a95613ab12a8e","account_uuid":"f9cf7fbe-cf66-48ec-81a1-c8b729fa5f80","session_id":"e31fbf72-94a9-4011-8e7b-c5b04f286a5e"}`
	t.Logf("full=%v empty_uuid=%v", isClaudeCodeClient("claude-cli/2.1.311 (external, sdk-cli)", uid), isClaudeCodeClient("claude-cli/2.1.311 (external, sdk-cli)", `{"device_id":"a","account_uuid":"","session_id":"b"}`))
	if !isClaudeCodeClient("claude-cli/2.1.311 (external, sdk-cli)", `{"device_id":"a","account_uuid":"","session_id":"b"}`) {
		t.Fatal("api-key 形状的 metadata 未被识别为 CLI")
	}
}
