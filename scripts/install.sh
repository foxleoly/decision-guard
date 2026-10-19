#!/usr/bin/env bash
# Installs decision-guard from this directory into ~/.decision-guard, links the skill and wires the agents.
# Idempotent. Every file it edits is backed up first (*.bak-decision-guard). The API key and verdict cache
# in ~/.decision-guard are never touched.
#
#   install.sh [--dry-run] [target ...]
#   no target: set up everything this machine can use: shared files, the skill, and the hook or extension of each agent
#              found (~/.omp or ~/.pi, ~/.config/opencode, ~/.claude, ~/.codex, ~/.copilot). Asks for a decision service
#              when none is configured and stdin is a terminal. Ends with a self-check.
#            "files" also installs the prebuilt binary for this machine from ../dist (checksum verified) as
#            ~/.decision-guard/bin/decision-guard; every agent hook and adapter runs that binary. It also removes the
#            Node runtime copies an older install left there (core.mjs, hook.mjs, web.mjs, web-page.html, archive.mjs).
#   targets: files skill pi opencode claude codex copilot   (name them to install only those)
#            opencode-ask  (never automatic) sets permission.bash "*" to "ask" so OpenCode can really prompt
#            archive       (never automatic) schedules the weekly log archive (macOS LaunchAgent, else a cron line)
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DG="$HOME/.decision-guard"
DRY=0
TARGETS=()
for arg in "$@"; do
	if [ "$arg" = "--dry-run" ]; then DRY=1; else TARGETS+=("$arg"); fi
done
AUTO=0
want() { [[ " ${TARGETS[*]} " == *" $1 "* ]]; }
run() { if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }
if [ ${#TARGETS[@]} -eq 0 ]; then
	AUTO=1
	TARGETS=(files skill)
	for pair in "pi|$HOME/.omp" "pi|$HOME/.pi" "opencode|$HOME/.config/opencode" "claude|$HOME/.claude" "codex|${CODEX_HOME:-$HOME/.codex}" "copilot|${COPILOT_HOME:-$HOME/.copilot}"; do
		if [ -d "${pair#*|}" ] && ! want "${pair%%|*}"; then TARGETS+=("${pair%%|*}"); fi
	done
	echo "setup: ${TARGETS[*]}"
fi

# Fail before writing anything.
if { want claude || want codex || want opencode-ask; } && ! command -v jq >/dev/null; then echo "error: jq is required to edit JSON agent config" >&2; exit 1; fi

# Picks the prebuilt binary for this machine from ../dist and checks it against SHA256SUMS; sets BIN_SRC.
# No silent fallback: a missing artifact or a checksum mismatch stops the install.
DIST="$(dirname "$SRC")/dist"
verify_binary() {
	local triple name want got
	case "$(uname -s)/$(uname -m)" in
	Darwin/arm64) triple=aarch64-apple-darwin ;;
	Darwin/x86_64) triple=x86_64-apple-darwin ;;
	Linux/x86_64) triple=x86_64-unknown-linux-gnu ;;
	Linux/aarch64 | Linux/arm64) triple=aarch64-unknown-linux-gnu ;;
	*) triple="$(uname -s)-$(uname -m)" ;;
	esac
	name="decision-guard-$triple"
	want=$(awk -v f="$name" '$2 == f { print $1 }' "$DIST/SHA256SUMS" 2>/dev/null || true)
	if [ ! -f "$DIST/$name" ] || [ -z "$want" ]; then
		echo "error: no prebuilt binary for $triple in $DIST (or it is missing from SHA256SUMS)." >&2
		echo "       build it on this machine with: $(dirname "$SRC")/rust/scripts/build-dist.sh" >&2
		exit 1
	fi
	if command -v sha256sum >/dev/null; then got=$(sha256sum "$DIST/$name" | awk '{ print $1 }'); else got=$(shasum -a 256 "$DIST/$name" | awk '{ print $1 }'); fi
	if [ "$got" != "$want" ]; then
		echo "error: checksum mismatch for $DIST/$name (SHA256SUMS says $want, file is $got); refusing to install it." >&2
		echo "       rebuild with $(dirname "$SRC")/rust/scripts/build-dist.sh or restore the file from git." >&2
		exit 1
	fi
	BIN_SRC="$DIST/$name"
	echo "ok   $name (sha256 verified)"
}
if want files; then verify_binary; fi

# Adds a PreToolUse (Bash) and a UserPromptSubmit entry (Claude/Codex hook-file format) unless decision-guard is
# already there. The prompt hook lets the guard know what the user asked for.
merge_hooks_json() { # file tool
	local file=$1 tool=$2 cur out
	if [ -f "$file" ]; then cur=$(jq . "$file")
	elif [ -d "$(dirname "$file")" ]; then cur='{}'
	else echo "skip $file ($(dirname "$file") missing)"; return; fi
	out=$(jq --arg cmd "\"\$HOME/.decision-guard/bin/decision-guard\" hook $tool" '
		def wired(ev): any(.hooks[ev][]?.hooks[]?; (.command // "") | contains("decision-guard/bin/decision-guard"));
		# entries from the old Node hook are switched to the binary in place
		((.hooks[]?[]?.hooks[]? | select((.command // "") | contains("decision-guard/hook.mjs")) | .command) |= $cmd)
		| (if wired("PreToolUse") then . else .hooks.PreToolUse += [{matcher: "Bash", hooks: [{type: "command", command: $cmd, timeout: 15}]}] end)
		| (if wired("UserPromptSubmit") then . else .hooks.UserPromptSubmit += [{hooks: [{type: "command", command: $cmd, timeout: 15}]}] end)' <<<"$cur")
	if [ "$out" = "$cur" ]; then echo "ok   $file (already wired)"; return; fi
	if [ "$DRY" = 1 ]; then echo "would edit $file:"; diff <(echo "$cur") <(echo "$out") || true; return; fi
	if [ -f "$file" ]; then cp "$file" "$file.bak-decision-guard"; fi
	echo "$out" > "$file.tmp" && mv "$file.tmp" "$file"
	echo "edit $file"
}

# -n: replacing a link that points at a directory must not create a link inside that directory.
link() { run mkdir -p "$(dirname "$2")"; run ln -sfn "$1" "$2"; echo "link $2"; }

# Asks once for the decision service when none is configured and a person is at the keyboard.
ask_service() {
	[ -s "$DG/key" ] || [ -s "$DG/config.json" ] || [ -n "${OPENAI_API_KEY:-}${DECISION_GUARD_BASE_URL:-}" ] && return 0
	if [ "$DRY" = 1 ] || [ ! -t 0 ]; then
		echo "note: no decision service yet; put an OpenAI key on the first line of $DG/key, or a base_url in $DG/config.json (chmod 600)"
		return 0
	fi
	local choice key url model
	read -r -p "Decision service: [1] OpenAI key  [2] your own server URL  [Enter] later: " choice
	case "$choice" in
	1) read -r -s -p "OpenAI key: " key; echo
		[ -n "$key" ] && (umask 077; printf '%s\n' "$key" > "$DG/key") && echo "saved $DG/key" ;;
	2) read -r -p "Full endpoint URL (path included): " url
		read -r -p "Model (Enter = default): " model
		read -r -s -p "API key (Enter = none): " key; echo
		[ -n "$url" ] && (umask 077; jq -n --arg u "$url" --arg m "$model" --arg k "$key" \
			'{base_url: $u} + (if $m != "" then {model: $m} else {} end) + (if $k != "" then {api_key: $k} else {} end)' > "$DG/config.json") && echo "saved $DG/config.json" ;;
	*) echo "skipped: until a service is set, commands pass through with a warning" ;;
	esac
	return 0
}

if want files; then
	run mkdir -p "$DG/adapters" "$DG/bin"
	run chmod 700 "$DG"
	# Runtime copies of the Node implementation this binary replaced; explicit names, never a glob.
	for stale in core.mjs hook.mjs web.mjs web-page.html archive.mjs; do
		if [ -f "$DG/$stale" ]; then
			run rm -f "$DG/$stale"
			echo "remove $DG/$stale (replaced by bin/decision-guard)"
			STALE=1
		fi
	done
	run cp "$SRC/adapters/pi.ts" "$SRC/adapters/opencode.js" "$DG/adapters/"
	# Copy then rename: overwriting a running binary in place breaks its code signature on macOS.
	run cp "$BIN_SRC" "$DG/bin/.decision-guard.new"
	run chmod 755 "$DG/bin/.decision-guard.new"
	run mv "$DG/bin/.decision-guard.new" "$DG/bin/decision-guard"
	echo "copy $DG   (review the log in a browser: $DG/bin/decision-guard web)"
	if [ "${STALE:-0}" = 1 ] && ! want claude && ! want codex && ! want copilot; then echo "note: agent hooks that still ran the removed hook.mjs need install.sh with no target (or claude, codex, copilot) to switch to the binary"; fi
	if grep -qs "archive.mjs" "$HOME/Library/LaunchAgents/com.decision-guard.archive.plist"; then echo "note: the weekly archive job still runs archive.mjs; re-run install.sh archive"; fi
	ask_service
fi
if want archive; then
	# Weekly archive of old log rows (decision-guard archive). macOS: a LaunchAgent, Sundays 03:30. Elsewhere: print a cron line.
	if ! want files && [ ! -x "$DG/bin/decision-guard" ]; then echo "note: $DG/bin/decision-guard is missing; run install.sh files first or the job has nothing to run"; fi
	if [ "$(uname)" = "Darwin" ]; then
		plist="$HOME/Library/LaunchAgents/com.decision-guard.archive.plist"
		run mkdir -p "$(dirname "$plist")"
		if [ "$DRY" = 0 ]; then
			cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.decision-guard.archive</string>
  <key>ProgramArguments</key><array><string>$DG/bin/decision-guard</string><string>archive</string></array>
  <key>StartCalendarInterval</key><dict><key>Weekday</key><integer>0</integer><key>Hour</key><integer>3</integer><key>Minute</key><integer>30</integer></dict>
  <key>StandardOutPath</key><string>$DG/archive.log</string>
  <key>StandardErrorPath</key><string>$DG/archive.log</string>
</dict></plist>
EOF
			launchctl bootout "gui/$(id -u)/com.decision-guard.archive" 2>/dev/null || true
			launchctl bootstrap "gui/$(id -u)" "$plist"
		fi
		echo "agent $plist   (weekly, Sunday 03:30, log: $DG/archive.log)"
	else
		echo "add this line to your crontab:  30 3 * * 0 $DG/bin/decision-guard archive >> $DG/archive.log 2>&1"
	fi
fi
if want pi; then
	linked=0
	for root in .omp .pi; do
		if [ -d "$HOME/$root" ]; then link "$DG/adapters/pi.ts" "$HOME/$root/agent/extensions/decision-guard.ts"; linked=1; fi
	done
	[ "$linked" = 1 ] || echo "skip pi (no ~/.omp or ~/.pi)"
fi
if want skill; then
	# Agents read SKILL.md from the checkout through a link, so a git pull updates it. Keep the checkout in place.
	for pair in "$HOME/.claude:skills" "${CODEX_HOME:-$HOME/.codex}:skills" "$HOME/.omp:agent/skills" "$HOME/.pi:agent/skills" "$HOME/.config/opencode:skills" "${COPILOT_HOME:-$HOME/.copilot}:skills"; do
		root=${pair%%:*}; dest="$root/${pair#*:}/decision-guard"
		[ -d "$root" ] || continue
		if [ -e "$dest" ] && [ ! -L "$dest" ]; then echo "skip $dest (a real directory is there; remove it to link)"; continue; fi
		link "$(dirname "$SRC")" "$dest"
	done
fi
if want opencode; then link "$DG/adapters/opencode.js" "$HOME/.config/opencode/plugins/decision-guard.js"; fi
if want opencode-ask; then
	# Real OpenCode prompts need bash set to "ask": the plugin then answers each request (allow = no prompt).
	# Without this the plugin can only reject. More specific rules such as "git push*" keep working.
	file="$HOME/.config/opencode/opencode.json"
	if [ ! -f "$file" ]; then echo "skip $file (missing)"; else
		out=$(jq 'if (.permission.bash | type) == "object" then .permission.bash["*"] = "ask" else .permission.bash = {"*": "ask"} end' "$file")
		if [ "$out" = "$(jq . "$file")" ]; then echo "ok   $file (bash already asks)"
		elif [ "$DRY" = 1 ]; then echo "would edit $file:"; diff <(jq . "$file") <(echo "$out") || true
		else cp "$file" "$file.bak-decision-guard"; echo "$out" > "$file.tmp" && mv "$file.tmp" "$file"; echo "edit $file"; fi
	fi
fi
if want claude; then merge_hooks_json "$HOME/.claude/settings.json" claude; fi
if want codex; then
	merge_hooks_json "${CODEX_HOME:-$HOME/.codex}/hooks.json" codex
	echo "Codex: open /hooks once and trust the new hook; it is skipped until reviewed."
fi
if want copilot; then
	# Copilot CLI reads its own hook file, so nothing to merge. PascalCase event names = Claude-compatible payloads.
	file="${COPILOT_HOME:-$HOME/.copilot}/hooks/decision-guard.json"
	run mkdir -p "$(dirname "$file")"
	if [ "$DRY" = 0 ]; then
		cat > "$file" <<'EOF'
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      { "type": "command", "matcher": "Bash", "bash": "\"$HOME/.decision-guard/bin/decision-guard\" hook copilot", "timeoutSec": 15 }
    ],
    "UserPromptSubmit": [
      { "type": "command", "bash": "\"$HOME/.decision-guard/bin/decision-guard\" hook copilot", "timeoutSec": 15 }
    ]
  }
}
EOF
	fi
	echo "file $file"
fi

if [ "$DRY" = 0 ] && want files; then
	# Deterministic rule, no model needed: a recursive delete must come back as "ask".
	verdict=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/decision-guard-smoke-test"},"cwd":"/tmp"}' | "$DG/bin/decision-guard" hook claude 2>/dev/null || true)
	case "$verdict" in
	*'"ask"'*) echo "check: recursive delete is held for approval: ok" ;;
	*) echo "check FAILED: the hook did not ask for 'rm -rf'; output was: ${verdict:-<empty>}" >&2; exit 1 ;;
	esac
fi
if [ "$DRY" = 0 ]; then echo "done: restart the agents you use so they load the hook."; fi
if [ "$AUTO" = 1 ]; then echo "optional: install.sh opencode-ask (real OpenCode prompts), install.sh archive (weekly log archive)"; fi
