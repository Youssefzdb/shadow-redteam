#!/bin/bash
TARGET_EMAIL="ambuguambuguambugu@gmail.com"
python modules/email_spoof_tester.py \
  --domain d17.tn \
  --from ceo@d17.tn \
  --to "$TARGET_EMAIL" \
  --smtp-port 2525 \
  --send
