#!/usr/bin/env bash
# PostToolUse hook: lint marketplace files after every Edit/Write.
# Runs ruff in check-only mode; errors are advisory (|| true).
ruff check warden/marketplace/ --ignore E501 --select E,F,W,I 2>&1 | head -20 || true
