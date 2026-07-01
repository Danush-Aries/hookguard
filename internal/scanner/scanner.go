// Package scanner walks a repository, parses .claude/settings.json, resolves
// every referenced hook script, and applies the rule set.
package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Danush-Aries/hookguard/internal/rules"
)

// Result is the top-level scan output.
type Result struct {
	Root       string           `json:"root"`
	SettingsAt string           `json:"settings_at,omitempty"`
	Hooks      []HookRecord     `json:"hooks"`
	Findings   []rules.Finding  `json:"findings"`
	Summary    Summary          `json:"summary"`
}

// Summary aggregates by severity.
type Summary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

// HookRecord is what hookguard extracted about one hook entry.
type HookRecord struct {
	Event      string `json:"event"`
	Matcher    string `json:"matcher,omitempty"`
	Type       string `json:"type"`
	Command    string `json:"command"`
	ScriptPath string `json:"script_path,omitempty"`
	Inline     bool   `json:"inline"`
}

// settingsFile mirrors the .claude/settings.json shape hookguard cares about.
// The upstream schema is a map of event names to arrays of matcher blocks,
// each of which contains a list of hook entries.
type settingsFile struct {
	Hooks map[string][]matcherBlock `json:"hooks"`
}

type matcherBlock struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// Scan walks root and returns a Result.
func Scan(root string) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	res := &Result{Root: abs, Hooks: []HookRecord{}, Findings: []rules.Finding{}}

	settingsPaths, err := findSettings(abs)
	if err != nil {
		return nil, err
	}
	if len(settingsPaths) == 0 {
		return res, nil
	}
	res.SettingsAt = settingsPaths[0]

	for _, sp := range settingsPaths {
		if err := scanOneSettings(sp, abs, res); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].RuleID != res.Findings[j].RuleID {
			return res.Findings[i].RuleID < res.Findings[j].RuleID
		}
		return res.Findings[i].ScriptPath < res.Findings[j].ScriptPath
	})
	for _, f := range res.Findings {
		switch f.Severity {
		case rules.SeverityInfo:
			res.Summary.Info++
		case rules.SeverityLow:
			res.Summary.Low++
		case rules.SeverityMedium:
			res.Summary.Medium++
		case rules.SeverityHigh:
			res.Summary.High++
		case rules.SeverityCritical:
			res.Summary.Critical++
		}
	}
	res.Summary.Total = len(res.Findings)
	return res, nil
}

// findSettings returns every .claude/settings.json (and settings.local.json)
// under root. Skips node_modules, .git, vendor.
func findSettings(root string) ([]string, error) {
	var out []string
	skip := map[string]bool{"node_modules": true, ".git": true, "vendor": true, "dist": true, "build": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && skip[d.Name()] {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base != "settings.json" && base != "settings.local.json" {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != ".claude" {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func scanOneSettings(settingsPath, root string, res *Result) error {
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	var sf settingsFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return fmt.Errorf("parse %s: %w", settingsPath, err)
	}
	allRules := rules.All()

	for event, blocks := range sf.Hooks {
		for _, b := range blocks {
			for _, h := range b.Hooks {
				rec := HookRecord{
					Event:   event,
					Matcher: b.Matcher,
					Type:    h.Type,
					Command: h.Command,
				}
				scriptBytes, scriptPath, inline := resolveHook(h.Command, filepath.Dir(settingsPath), root)
				rec.ScriptPath = scriptPath
				rec.Inline = inline
				res.Hooks = append(res.Hooks, rec)

				meta := rules.HookMeta{
					Event:      event,
					Command:    h.Command,
					ScriptPath: scriptPath,
				}
				for _, r := range allRules {
					res.Findings = append(res.Findings, r.Match(scriptBytes, meta)...)
				}
			}
		}
	}
	return nil
}

// pathRe extracts a shell-script or python-script path referenced in a hook command.
var pathRe = regexp.MustCompile(`([~./]?[\w./-]+\.(?:sh|bash|zsh|py|pl|rb|js|mjs|ts))`)

// resolveHook decides whether the command references an on-disk script or is
// itself an inline shell command. If it's a path, the file is read.
func resolveHook(command, settingsDir, root string) ([]byte, string, bool) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return []byte(command), "", true
	}
	// If the command starts with a path-like token to an existing file, prefer that.
	if p := extractScriptPath(trimmed, settingsDir, root); p != "" {
		b, err := os.ReadFile(p)
		if err == nil {
			return b, p, false
		}
	}
	// Otherwise treat the entire command as inline shell.
	return []byte(command), "", true
}

func extractScriptPath(cmd, settingsDir, root string) string {
	// Look for the first .sh / .py / etc. token that resolves to a real file.
	for _, m := range pathRe.FindAllString(cmd, -1) {
		p := expandPath(m, settingsDir, root)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	// Fall back to the first token if it happens to be a path.
	first := strings.Fields(cmd)
	if len(first) == 0 {
		return ""
	}
	tok := first[0]
	// Strip common prefixes like "bash", "sh", "python3".
	if isInterp(tok) && len(first) > 1 {
		tok = first[1]
	}
	p := expandPath(tok, settingsDir, root)
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return p
	}
	return ""
}

func isInterp(s string) bool {
	switch s {
	case "bash", "sh", "zsh", "dash", "python", "python3", "python2", "perl", "ruby", "node":
		return true
	}
	return false
}

func expandPath(p, settingsDir, root string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	if strings.HasPrefix(p, "$CLAUDE_PROJECT_DIR/") {
		p = filepath.Join(root, strings.TrimPrefix(p, "$CLAUDE_PROJECT_DIR/"))
	}
	if !filepath.IsAbs(p) {
		// Try relative to settings dir, then relative to root.
		candidate := filepath.Join(settingsDir, p)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		return filepath.Join(root, p)
	}
	return p
}

// HighestSeverity returns the worst severity across findings.
func (r *Result) HighestSeverity() rules.Severity {
	switch {
	case r.Summary.Critical > 0:
		return rules.SeverityCritical
	case r.Summary.High > 0:
		return rules.SeverityHigh
	case r.Summary.Medium > 0:
		return rules.SeverityMedium
	case r.Summary.Low > 0:
		return rules.SeverityLow
	case r.Summary.Info > 0:
		return rules.SeverityInfo
	}
	return ""
}
