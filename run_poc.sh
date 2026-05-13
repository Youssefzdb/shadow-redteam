#!/bin/bash
# Shadow Red Team - Email Spoofing PoC Launcher
# Edit RELAY_USER and RELAY_PASS before running

RELAY_USER="yourgmail@gmail.com"
RELAY_PASS="your-app-password-here"

python modules/email_spoof_tester.py \
  --relay-user "$RELAY_USER" \
  --relay-pass "$RELAY_PASS"
