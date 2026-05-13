#!/bin/bash
# Shadow Red Team - Email Spoofing PoC Launcher

RELAY_USER="ambuguambuguambugu@gmail.com"
RELAY_PASS="osvi pixf cshk oaeh"

python modules/email_spoof_tester.py \
  --relay-user "$RELAY_USER" \
  --relay-pass "$RELAY_PASS"
