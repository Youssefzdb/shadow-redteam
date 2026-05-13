# 🔴 Shadow Red Team Toolkit

> Private offensive security toolkit for authorized red team engagements.
> `github.com/Youssefzdb/shadow-redteam` — PRIVATE

---

## ⚠️ Legal Notice

> For authorized penetration testing only.
> All tools require written authorization from the target organization.

---

## 🧰 Modules

| Module | Description |
|--------|-------------|
| 📧 `email_spoof_tester.py` | SPF/DKIM/DMARC checker + local SMTP spoof sender |

---

## 📦 Installation

```bash
git clone https://github.com/Youssefzdb/shadow-redteam
cd shadow-redteam
pip install -r requirements.txt
apt install postfix -y
```

---

## 🚀 Usage

```bash
# Check domain misconfiguration
python modules/email_spoof_tester.py --domain target.com

# Send PoC spoofed email
python modules/email_spoof_tester.py \
  --domain target.com \
  --from ceo@target.com \
  --to proof@youremail.com \
  --send

# Show local SMTP setup guide
python modules/email_spoof_tester.py --domain target.com --setup
```

---

*Shadow Red Team Toolkit — Authorized engagements only. 🔥*
