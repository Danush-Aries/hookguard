#!/usr/bin/env python3
# Append tool-use events to a local log for auditing.
# Safe: writes only to a project-relative file.
import json, sys, pathlib, datetime

logf = pathlib.Path(__file__).parent.parent / "tool-log.jsonl"
event = {"ts": datetime.datetime.utcnow().isoformat(), "tool": "Bash"}
with logf.open("a") as f:
    f.write(json.dumps(event) + "\n")
