#!/usr/bin/env python3
"""
Shadow OSINT — Email Spoofing Tester
SPF/DKIM/DMARC Checker + Local SMTP Spoof Sender
For authorized penetration testing only.
"""

import smtplib
import dns.resolver
import subprocess
import sys
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class C:
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# ─── 1. CHECK SPF / DKIM / DMARC ─────────────────────────
def check_domain(domain):
    print(f"\n{C.BOLD}{'━'*55}{C.RESET}")
    print(f"  🔍  DNS Misconfiguration Check: {C.CYAN}{domain}{C.RESET}")
    print(f"{C.BOLD}{'━'*55}{C.RESET}\n")

    results = {"spf": None, "dmarc": None, "dkim": None}

    # ── SPF ──
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for r in answers:
            txt = r.to_text().strip('"')
            if 'v=spf1' in txt:
                spf_found = True
                if '-all' in txt:
                    print(f"  {C.GREEN}✅  SPF: STRICT (-all) — spoofing blocked{C.RESET}")
                    print(f"       {txt[:80]}")
                    results["spf"] = "strict"
                elif '~all' in txt:
                    print(f"  {C.YELLOW}⚠️   SPF: SOFT (~all) — emails may land in spam but NOT blocked{C.RESET}")
                    print(f"       {txt[:80]}")
                    results["spf"] = "soft"
                elif '?all' in txt or '+all' in txt:
                    print(f"  {C.RED}🔴  SPF: WEAK (+all/?all) — SPOOFING POSSIBLE!{C.RESET}")
                    results["spf"] = "weak"
                else:
                    print(f"  {C.YELLOW}⚠️   SPF: EXISTS but no -all{C.RESET}")
                    results["spf"] = "weak"
        if not spf_found:
            print(f"  {C.RED}🔴  SPF: NOT FOUND — SPOOFING POSSIBLE!{C.RESET}")
            results["spf"] = "missing"
    except Exception as e:
        print(f"  {C.RED}🔴  SPF: ERROR ({e}){C.RESET}")
        results["spf"] = "missing"

    # ── DMARC ──
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in answers:
            txt = r.to_text().strip('"')
            if 'v=DMARC1' in txt:
                if 'p=reject' in txt:
                    print(f"  {C.GREEN}✅  DMARC: REJECT — spoofed emails blocked{C.RESET}")
                    results["dmarc"] = "reject"
                elif 'p=quarantine' in txt:
                    print(f"  {C.YELLOW}⚠️   DMARC: QUARANTINE — may go to spam{C.RESET}")
                    results["dmarc"] = "quarantine"
                elif 'p=none' in txt:
                    print(f"  {C.RED}🔴  DMARC: p=none — NO ENFORCEMENT! SPOOFING POSSIBLE!{C.RESET}")
                    results["dmarc"] = "none"
                print(f"       {txt[:80]}")
    except:
        print(f"  {C.RED}🔴  DMARC: NOT FOUND — NO PROTECTION!{C.RESET}")
        results["dmarc"] = "missing"

    # ── DKIM (common selectors) ──
    selectors = ["default", "google", "mail", "smtp", "k1", "selector1", "selector2", "dkim"]
    dkim_found = False
    for sel in selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT')
            print(f"  {C.YELLOW}⚠️   DKIM: Found selector '{sel}' (may be valid){C.RESET}")
            dkim_found = True
            results["dkim"] = sel
            break
        except:
            pass
    if not dkim_found:
        print(f"  {C.RED}🔴  DKIM: NOT CONFIGURED — emails won't be signed{C.RESET}")
        results["dkim"] = "missing"

    # ── Verdict ──
    print(f"\n  {C.BOLD}📊 VERDICT:{C.RESET}")
    vulnerable = results["spf"] in ["missing", "weak"] or results["dmarc"] in ["missing", "none"]
    if vulnerable:
        print(f"  {C.RED}{C.BOLD}🚨 DOMAIN IS VULNERABLE TO EMAIL SPOOFING!{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}🛡️  Domain has email protection configured{C.RESET}")

    return results, vulnerable

# ─── 2. SETUP LOCAL POSTFIX ───────────────────────────────
def setup_local_smtp():
    print(f"\n{C.BOLD}{'━'*55}{C.RESET}")
    print(f"  📮  Local SMTP Setup (Postfix)")
    print(f"{C.BOLD}{'━'*55}{C.RESET}\n")

    print(f"  {C.YELLOW}Run these commands on your Kali machine:{C.RESET}\n")
    print(f"""  {C.CYAN}# 1. Install Postfix{C.RESET}
  apt install postfix -y
  # Choose: "Internet Site" → enter your domain

  {C.CYAN}# 2. Configure relay (no auth needed for local testing){C.RESET}
  echo "relayhost =" >> /etc/postfix/main.cf
  echo "mynetworks = 127.0.0.0/8" >> /etc/postfix/main.cf

  {C.CYAN}# 3. Start Postfix{C.RESET}
  systemctl start postfix
  systemctl enable postfix

  {C.CYAN}# 4. Test local send{C.RESET}
  echo "Test" | mail -s "Test" your@email.com

  {C.CYAN}# 5. Run spoof test{C.RESET}
  python email_spoof_tester.py --domain target.com \\
    --from ceo@target.com \\
    --to proof@youremail.com \\
    --send
""")

# ─── 3. SEND SPOOF EMAIL ──────────────────────────────────
def send_spoof_email(from_addr, to_addr, domain, subject=None, body=None, smtp_host="127.0.0.1", smtp_port=25):
    print(f"\n{C.BOLD}{'━'*55}{C.RESET}")
    print(f"  📧  Sending Spoofed Email (PoC)")
    print(f"{C.BOLD}{'━'*55}{C.RESET}\n")

    if not subject:
        subject = f"[SECURITY TEST] Email Spoofing PoC — {domain}"

    if not body:
        body = f"""
⚠️ PENETRATION TEST — AUTHORIZED SECURITY ASSESSMENT ⚠️

This email was sent as part of an authorized security assessment.

Finding: Email Spoofing Vulnerability
Domain:  {domain}
From:    {from_addr}
Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This email appears to originate from {from_addr} but was sent
by a third party — demonstrating that the domain {domain}
is vulnerable to email spoofing attacks.

An attacker could use this to:
- Impersonate executives (CEO fraud / BEC)
- Send phishing emails that bypass filters
- Damage brand reputation

Recommendation:
- Set SPF record with -all
- Enable DMARC with p=reject
- Configure DKIM signing

— Shadow OSINT Engine | Authorized Red Team Assessment
"""

    msg = MIMEMultipart("alternative")
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg["X-Mailer"] = "Shadow-OSINT-Tester/3.0"
    msg.attach(MIMEText(body, "plain"))

    try:
        print(f"  From    : {C.YELLOW}{from_addr}{C.RESET}")
        print(f"  To      : {C.YELLOW}{to_addr}{C.RESET}")
        print(f"  SMTP    : {smtp_host}:{smtp_port}")
        print(f"  Subject : {subject}\n")

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.sendmail(from_addr, [to_addr], msg.as_string())
            print(f"  {C.GREEN}{C.BOLD}✅ Email sent successfully!{C.RESET}")
            print(f"  {C.CYAN}Check inbox of {to_addr}{C.RESET}")
            return True

    except ConnectionRefusedError:
        print(f"  {C.RED}❌ Connection refused — is Postfix running?{C.RESET}")
        print(f"  {C.YELLOW}Run: systemctl start postfix{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}❌ Error: {e}{C.RESET}")

    return False

# ─── 4. GENERATE REPORT ───────────────────────────────────
def generate_report(domain, results, vulnerable, sent=False, from_addr=None, to_addr=None):
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    filename = f"reports/spoof_{domain}_{ts}.md"

    import os
    os.makedirs("reports", exist_ok=True)

    report = f"""# Email Spoofing Assessment Report

**Target Domain:** `{domain}`
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** Shadow OSINT Engine v3.0

---

## DNS Configuration

| Record | Status |
|--------|--------|
| SPF    | {results.get('spf', 'unknown')} |
| DMARC  | {results.get('dmarc', 'unknown')} |
| DKIM   | {results.get('dkim', 'unknown')} |

## Verdict

{'🚨 **VULNERABLE** — Domain can be spoofed' if vulnerable else '✅ Domain has email protection'}

## Proof of Concept

{'✅ Spoofed email sent from `' + str(from_addr) + '` to `' + str(to_addr) + '`' if sent else 'No email sent (--send flag not used)'}

## Recommendations

1. Set SPF: `v=spf1 include:_spf.{domain} -all`
2. Set DMARC: `v=DMARC1; p=reject; rua=mailto:dmarc@{domain}`
3. Configure DKIM signing on mail server

---
*Generated by Shadow OSINT Engine — Authorized Assessment*
"""

    with open(filename, 'w') as f:
        f.write(report)

    print(f"\n  {C.GREEN}📄 Report saved: {filename}{C.RESET}")

# ─── MAIN ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Shadow Email Spoofing Tester')
    parser.add_argument('--domain',    required=True, help='Target domain (e.g. target.com)')
    parser.add_argument('--from',      dest='from_addr', help='Spoofed from address')
    parser.add_argument('--to',        dest='to_addr',   help='Recipient email (yours)')
    parser.add_argument('--subject',   help='Email subject')
    parser.add_argument('--smtp-host', default='127.0.0.1', help='SMTP host (default: 127.0.0.1)')
    parser.add_argument('--smtp-port', default=25, type=int, help='SMTP port (default: 25)')
    parser.add_argument('--send',      action='store_true', help='Actually send the email')
    parser.add_argument('--setup',     action='store_true', help='Show Postfix setup instructions')
    args = parser.parse_args()

    print(f"\n{C.CYAN}{C.BOLD}Shadow Email Spoofing Tester v1.0{C.RESET}")
    print(f"{C.YELLOW}For authorized penetration testing only{C.RESET}\n")

    # Check domain
    results, vulnerable = check_domain(args.domain)

    # Show setup instructions
    if args.setup:
        setup_local_smtp()

    sent = False
    # Send if requested
    if args.send:
        if not args.from_addr or not args.to_addr:
            print(f"\n  {C.RED}❌ --from and --to required with --send{C.RESET}")
            sys.exit(1)
        sent = send_spoof_email(
            args.from_addr, args.to_addr, args.domain,
            args.subject, None, args.smtp_host, args.smtp_port
        )

    # Generate report
    generate_report(args.domain, results, vulnerable, sent, args.from_addr, args.to_addr)

if __name__ == "__main__":
    main()
