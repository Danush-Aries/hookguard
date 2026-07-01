// Package rules defines the static analysis rules that hookguard applies
// to Claude Code hook scripts. Each Rule inspects the raw script bytes plus
// hook metadata (which event triggered it) and returns zero or more Findings.
package rules

import (
	"regexp"
	"strings"
)

// Severity classifies how dangerous a finding is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// HookMeta describes where a hook script came from inside .claude/settings.json.
type HookMeta struct {
	// Event is the Claude Code hook event, e.g. "SessionStart",
	// "PreToolUse", "PostToolUse", "Stop", "SubagentStop".
	Event string
	// Command is the raw command string configured for the hook.
	Command string
	// ScriptPath is the resolved on-disk path of the referenced script,
	// or empty if the hook is an inline shell command.
	ScriptPath string
}

// Finding is a single rule hit.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
	Event      string   `json:"event,omitempty"`
	ScriptPath string   `json:"script_path,omitempty"`
	Line       int      `json:"line,omitempty"`
	Snippet    string   `json:"snippet,omitempty"`
}

// Rule is the matcher interface. Match returns Findings for any hits.
type Rule struct {
	ID          string
	Severity    Severity
	Title       string
	Description string
	Match       func(script []byte, meta HookMeta) []Finding
}

// All returns every rule hookguard ships with, in stable order.
func All() []Rule {
	return []Rule{
		hg001RemoteCodeExec(),
		hg002SessionStartCredTheft(),
		hg003EnvExfil(),
		hg004Base64Exec(),
		hg005SelfPersistence(),
		hg006OpaqueScript(),
		hg007TmpWriteNoCleanup(),
		hg008BroadChmod(),
	}
}

// ByID returns the rule matching id, or nil.
func ByID(id string) *Rule {
	for _, r := range All() {
		if r.ID == id {
			return &r
		}
	}
	return nil
}

// ---------- helpers ----------

func lineOf(script []byte, idx int) (int, string) {
	if idx < 0 || idx > len(script) {
		return 0, ""
	}
	line := 1
	start := 0
	for i := 0; i < idx; i++ {
		if script[i] == '\n' {
			line++
			start = i + 1
		}
	}
	end := idx
	for end < len(script) && script[end] != '\n' {
		end++
	}
	return line, strings.TrimSpace(string(script[start:end]))
}

func findAllRegex(script []byte, re *regexp.Regexp) [][]int {
	return re.FindAllIndex(script, -1)
}

// ---------- HG001: remote code exec via curl|sh, wget|bash, eval $() ----------

var (
	reCurlPipeShell = regexp.MustCompile(`(?i)(curl|wget)\s+[^\n|;&]*\|\s*(sh|bash|zsh|dash|ash|python[0-9.]*|perl|ruby|node)\b`)
	reEvalSubshell  = regexp.MustCompile(`(?i)\beval\s+["']?\$\(`)
	reEvalBackTick  = regexp.MustCompile("(?i)\\beval\\s+[\"']?`")
)

func hg001RemoteCodeExec() Rule {
	return Rule{
		ID:          "HG001",
		Severity:    SeverityCritical,
		Title:       "Remote code execution via download-and-run",
		Description: "Hook downloads a payload and pipes it to a shell interpreter (curl|sh, wget|bash) or evaluates a subshell.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			for _, re := range []*regexp.Regexp{reCurlPipeShell, reEvalSubshell, reEvalBackTick} {
				for _, m := range findAllRegex(script, re) {
					ln, snip := lineOf(script, m[0])
					out = append(out, Finding{
						RuleID:     "HG001",
						Severity:   SeverityCritical,
						Title:      "Remote code execution via download-and-run",
						Message:    "Hook fetches remote content and pipes it directly to an interpreter. This is the canonical RCE pattern seen in CVE-2026-XXXX.",
						Event:      meta.Event,
						ScriptPath: meta.ScriptPath,
						Line:       ln,
						Snippet:    snip,
					})
				}
			}
			return out
		},
	}
}

// ---------- HG002: SessionStart credential theft / reverse shell ----------

var (
	reWritesSSH       = regexp.MustCompile(`(?i)(>|>>|tee|cp|mv|cat\s+>)\s*[^;|&\n]*(\~/\.ssh/|\$HOME/\.ssh/|/\.ssh/authorized_keys)`)
	reWritesAWS       = regexp.MustCompile(`(?i)(>|>>|tee|cp|mv)\s*[^;|&\n]*(\~/\.aws/credentials|\$HOME/\.aws/credentials)`)
	reWritesGH        = regexp.MustCompile(`(?i)(>|>>|tee|cp|mv)\s*[^;|&\n]*(\~/\.config/gh/|\$HOME/\.config/gh/)`)
	reReverseShellNC  = regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b[^;\n]*\s+-e\b`)
	reReverseShellBTC = regexp.MustCompile(`(?i)bash\s+-i\s*>&?\s*/dev/tcp/`)
	rePySocket        = regexp.MustCompile(`(?i)socket\.socket\([^)]*\)[^\n]*connect\(`)
)

func hg002SessionStartCredTheft() Rule {
	return Rule{
		ID:          "HG002",
		Severity:    SeverityHigh,
		Title:       "SessionStart hook touches credentials or opens reverse shell",
		Description: "SessionStart hooks run at every Claude Code launch. Writing to ~/.ssh, ~/.aws, or opening a reverse shell there is the May-2026 attack pattern.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			isSession := strings.EqualFold(meta.Event, "SessionStart")
			checks := []*regexp.Regexp{reWritesSSH, reWritesAWS, reWritesGH, reReverseShellNC, reReverseShellBTC, rePySocket}
			for _, re := range checks {
				for _, m := range findAllRegex(script, re) {
					ln, snip := lineOf(script, m[0])
					msg := "Hook writes to credential stores or opens a reverse shell."
					sev := SeverityHigh
					if isSession {
						msg = "SessionStart hook writes to credential stores or opens a reverse shell — matches CVE-2026-XXXX."
						sev = SeverityCritical
					}
					out = append(out, Finding{
						RuleID:     "HG002",
						Severity:   sev,
						Title:      "SessionStart hook touches credentials or opens reverse shell",
						Message:    msg,
						Event:      meta.Event,
						ScriptPath: meta.ScriptPath,
						Line:       ln,
						Snippet:    snip,
					})
				}
			}
			return out
		},
	}
}

// ---------- HG003: env exfil ----------

var (
	reEnvPipeCurl = regexp.MustCompile(`(?i)\b(env|printenv|export\s+-p|set)\b[^\n]*\|\s*(curl|wget|nc|ncat)\b`)
	reEnvInCurl   = regexp.MustCompile(`(?i)\bcurl\b[^\n]*(--data|-d|-F|--data-binary|--data-urlencode)[^\n]*\$\(\s*(env|printenv)\b`)
)

func hg003EnvExfil() Rule {
	return Rule{
		ID:          "HG003",
		Severity:    SeverityHigh,
		Title:       "Environment variables exfiltrated over network",
		Description: "Hook captures the process environment and ships it to a remote host.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			for _, re := range []*regexp.Regexp{reEnvPipeCurl, reEnvInCurl} {
				for _, m := range findAllRegex(script, re) {
					ln, snip := lineOf(script, m[0])
					out = append(out, Finding{
						RuleID:     "HG003",
						Severity:   SeverityHigh,
						Title:      "Environment variables exfiltrated over network",
						Message:    "Hook pipes env/printenv output to curl/wget/nc — likely secret exfiltration.",
						Event:      meta.Event,
						ScriptPath: meta.ScriptPath,
						Line:       ln,
						Snippet:    snip,
					})
				}
			}
			return out
		},
	}
}

// ---------- HG004: base64-decoded execution ----------

var (
	reBase64Exec = regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sh|bash|zsh|python[0-9.]*|perl|ruby|node)\b`)
	rePyB64Exec  = regexp.MustCompile(`(?i)exec\s*\(\s*base64\.b64decode\(`)
)

func hg004Base64Exec() Rule {
	return Rule{
		ID:          "HG004",
		Severity:    SeverityMedium,
		Title:       "Base64-decoded payload executed",
		Description: "Hook decodes a base64 blob and pipes it to an interpreter — classic obfuscated-payload pattern.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			for _, re := range []*regexp.Regexp{reBase64Exec, rePyB64Exec} {
				for _, m := range findAllRegex(script, re) {
					ln, snip := lineOf(script, m[0])
					out = append(out, Finding{
						RuleID:     "HG004",
						Severity:   SeverityMedium,
						Title:      "Base64-decoded payload executed",
						Message:    "Hook decodes base64 and executes it. Obfuscation indicator.",
						Event:      meta.Event,
						ScriptPath: meta.ScriptPath,
						Line:       ln,
						Snippet:    snip,
					})
				}
			}
			return out
		},
	}
}

// ---------- HG005: hook modifies its own script (self-persistence) ----------

func hg005SelfPersistence() Rule {
	return Rule{
		ID:          "HG005",
		Severity:    SeverityMedium,
		Title:       "Hook modifies its own script (self-persistence)",
		Description: "Hook writes back to its own script path or to .claude/settings.json — persistence indicator.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			// Any write to .claude/settings.json is suspicious.
			reSettings := regexp.MustCompile(`(?i)(>|>>|tee|cp|mv)\s*[^;|&\n]*\.claude/settings\.json`)
			for _, m := range findAllRegex(script, reSettings) {
				ln, snip := lineOf(script, m[0])
				out = append(out, Finding{
					RuleID:     "HG005",
					Severity:   SeverityMedium,
					Title:      "Hook modifies its own script (self-persistence)",
					Message:    "Hook writes to .claude/settings.json — persistence / self-modification indicator.",
					Event:      meta.Event,
					ScriptPath: meta.ScriptPath,
					Line:       ln,
					Snippet:    snip,
				})
			}
			// Direct write to the hook's own script path.
			if meta.ScriptPath != "" {
				base := meta.ScriptPath
				if i := strings.LastIndex(base, "/"); i >= 0 {
					base = base[i+1:]
				}
				if base != "" {
					reSelf := regexp.MustCompile(`(?i)(>|>>|tee|cp|mv)\s*[^;|&\n]*` + regexp.QuoteMeta(base))
					for _, m := range findAllRegex(script, reSelf) {
						ln, snip := lineOf(script, m[0])
						out = append(out, Finding{
							RuleID:     "HG005",
							Severity:   SeverityMedium,
							Title:      "Hook modifies its own script (self-persistence)",
							Message:    "Hook rewrites its own script file — persistence indicator.",
							Event:      meta.Event,
							ScriptPath: meta.ScriptPath,
							Line:       ln,
							Snippet:    snip,
						})
					}
				}
			}
			return out
		},
	}
}

// ---------- HG006: opaque script (no shebang, no comments) ----------

func hg006OpaqueScript() Rule {
	return Rule{
		ID:          "HG006",
		Severity:    SeverityLow,
		Title:       "Hook script is opaque (no shebang, no comments)",
		Description: "Script has neither a shebang line nor any comment — harder to review, higher supply-chain risk.",
		Match: func(script []byte, meta HookMeta) []Finding {
			trimmed := strings.TrimSpace(string(script))
			if trimmed == "" {
				return nil
			}
			hasShebang := strings.HasPrefix(trimmed, "#!")
			hasComment := false
			for _, line := range strings.Split(trimmed, "\n") {
				l := strings.TrimSpace(line)
				if strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "#!") {
					hasComment = true
					break
				}
			}
			if hasShebang || hasComment {
				return nil
			}
			// Only flag if the script is non-trivial (>1 real line).
			nonEmpty := 0
			for _, line := range strings.Split(trimmed, "\n") {
				if strings.TrimSpace(line) != "" {
					nonEmpty++
				}
			}
			if nonEmpty < 2 {
				return nil
			}
			return []Finding{{
				RuleID:     "HG006",
				Severity:   SeverityLow,
				Title:      "Hook script is opaque (no shebang, no comments)",
				Message:    "Script lacks a shebang and any comments. Add documentation so reviewers can audit intent.",
				Event:      meta.Event,
				ScriptPath: meta.ScriptPath,
				Line:       1,
				Snippet:    firstLine(trimmed),
			}}
		},
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------- HG007: writes /tmp without cleanup ----------

var (
	reTmpWrite = regexp.MustCompile(`(?i)(>|>>|tee|cp|mv|touch|mkdir|mktemp)\s+[^;|&\n]*/tmp/`)
	reTmpClean = regexp.MustCompile(`(?i)\brm\b[^\n]*\s/tmp/`)
	reTrap     = regexp.MustCompile(`(?i)\btrap\b[^\n]*\s(EXIT|INT|TERM)`)
)

func hg007TmpWriteNoCleanup() Rule {
	return Rule{
		ID:          "HG007",
		Severity:    SeverityInfo,
		Title:       "Hook writes to /tmp without cleanup",
		Description: "Hook writes files under /tmp but has no matching rm or trap-based cleanup.",
		Match: func(script []byte, meta HookMeta) []Finding {
			hits := findAllRegex(script, reTmpWrite)
			if len(hits) == 0 {
				return nil
			}
			if reTmpClean.Match(script) || reTrap.Match(script) {
				return nil
			}
			m := hits[0]
			ln, snip := lineOf(script, m[0])
			return []Finding{{
				RuleID:     "HG007",
				Severity:   SeverityInfo,
				Title:      "Hook writes to /tmp without cleanup",
				Message:    "Hook creates files under /tmp with no cleanup. Not malicious on its own but leaves forensic residue.",
				Event:      meta.Event,
				ScriptPath: meta.ScriptPath,
				Line:       ln,
				Snippet:    snip,
			}}
		},
	}
}

// ---------- HG008: chmod 777 / broad perms ----------

var reBroadChmod = regexp.MustCompile(`(?i)\bchmod\s+(-R\s+)?(777|666|a\+w|a=rwx|o\+w)\b`)

func hg008BroadChmod() Rule {
	return Rule{
		ID:          "HG008",
		Severity:    SeverityMedium,
		Title:       "Hook grants world-writable permissions",
		Description: "Hook uses chmod 777 / 666 / a+w — grants write access to any local user.",
		Match: func(script []byte, meta HookMeta) []Finding {
			var out []Finding
			for _, m := range findAllRegex(script, reBroadChmod) {
				ln, snip := lineOf(script, m[0])
				out = append(out, Finding{
					RuleID:     "HG008",
					Severity:   SeverityMedium,
					Title:      "Hook grants world-writable permissions",
					Message:    "chmod 777 / 666 / a+w opens files to every local user. Tighten to 600 or 700.",
					Event:      meta.Event,
					ScriptPath: meta.ScriptPath,
					Line:       ln,
					Snippet:    snip,
				})
			}
			return out
		},
	}
}
