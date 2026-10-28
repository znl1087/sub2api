package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeSafeguardsCtx(t *testing.T, clientOS string) map[string]any {
	t.Helper()
	t.Setenv("SUB2API_CLIENT_USER", "neil")
	raw, err := buildSafeguardsBlock(clientOS)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var blocks []map[string]any
	if err := json.Unmarshal(raw, &blocks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return blocks[0]["classifier_context"].(map[string]any)
}

// Windows 客户端的路径必须渲染成 Windows/Git-Bash 形态，否则与 platform 自相矛盾。
func TestBuildSafeguardsPathsFollowWindowsClient(t *testing.T) {
	ctx := decodeSafeguardsCtx(t, "Windows")
	if got := ctx["home_dir"]; got != "/c/Users/neil" {
		t.Fatalf("home_dir = %v", got)
	}
	if got := ctx["user_identity"]; got != "neil" {
		t.Fatalf("user_identity = %v", got)
	}
	cwd := ctx["live_cwd"].(string)
	if want := "/c/Users/neil/"; len(cwd) <= len(want) || cwd[:len(want)] != want {
		t.Fatalf("live_cwd not under client home: %s", cwd)
	}
	// 同源：四处路径一致
	if ctx["git_state"].(map[string]any)["cwd"] != cwd {
		t.Fatal("git_state.cwd differs from live_cwd")
	}
	if ctx["trusted_directories"].(map[string]any)["primary"].(map[string]any)["path"] != cwd {
		t.Fatal("trusted primary differs from live_cwd")
	}
	roots := ctx["rule_roots"].(map[string]any)
	if roots["userSettings"] != "/c/Users/neil/.claude" {
		t.Fatalf("userSettings = %v", roots["userSettings"])
	}
	if roots["cliArg"] != cwd {
		t.Fatal("cliArg differs from live_cwd")
	}
	if ctx["case_insensitive_paths"] != true {
		t.Fatal("case_insensitive_paths should be true for windows")
	}
}

// macOS 客户端走 /Users/<user>。
func TestBuildSafeguardsPathsFollowDarwinClient(t *testing.T) {
	ctx := decodeSafeguardsCtx(t, "macOS")
	if got := ctx["home_dir"]; got != "/Users/neil" {
		t.Fatalf("home_dir = %v", got)
	}
	if ctx["platform"] != "darwin" {
		t.Fatalf("platform = %v", ctx["platform"])
	}
}

// 没有客户端 OS 线索时回落网关自身平台，路径与之保持同形。
func TestBuildSafeguardsPathsFallBackToGatewayPlatform(t *testing.T) {
	ctx := decodeSafeguardsCtx(t, "")
	if got, want := ctx["platform"], claudePlatform(""); got != want {
		t.Fatalf("platform = %v want %v", got, want)
	}
	home := ctx["home_dir"].(string)
	if claudePlatform("") != "linux" && !strings.Contains(home, "Users") {
		t.Fatalf("non-linux gateway produced odd home_dir: %v", home)
	}
}
