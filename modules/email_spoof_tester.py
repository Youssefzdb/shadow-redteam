#!/usr/bin/env python3
"""
Shadow Red Team — Email Spoofing Tester v2.0
SPF/DKIM/DMARC Checker + Gmail Relay Spoof Sender
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
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def check_domain(domain):
    print(f"\n{C.BOLD}{'━'*55}{C.RESET}")
    print(f"  🔍  DNS Check: {C.CYAN}{domain}{C.RESET}")
    print(f"{C.BOLD}{'━'*55}{C.RESET}\n")
    results = {"spf": None, "dmarc": None, "dkim": None}

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for r in answers:
            txt = r.to_text().strip('"')
            if 'v=spf1' in txt:
                spf_found = True
                if '-all' in txt:
                    print(f"  {C.GREEN}✅  SPF: STRICT{C.RESET}")
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

    selectors = ["default", "google", "mail", "smtp", "k1", "selector1", "selector2"]
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
    print(f"\n  {'🚨 VULNERABLE TO EMAIL SPOOFING!' if vulnerable else '🛡️  Protected'}")
    return results, vulnerable


def send_spoof_email(from_addr, to_addr, domain, subject=None, body=None,
                     relay_user=None, relay_pass=None,
                     smtp_host="127.0.0.1", smtp_port=2525):

    print(f"\n{C.BOLD}{'━'*55}{C.RESET}")
    print(f"  📧  Sending Spoofed Email")
    print(f"{C.BOLD}{'━'*55}{C.RESET}\n")

    if not subject:
        subject = f"[SECURITY TEST] Email Spoofing PoC — {domain}"
    if not body:
        body = f"""PENETRATION TEST — AUTHORIZED ASSESSMENT

Finding: Email Spoofing Vulnerability
Domain:  {domain}
From:    {from_addr} (SPOOFED)
Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This email appears to come from {from_addr} but was sent
by a third party — proving {domain} has no email protection.

Risk: CEO fraud, phishing, brand impersonation.

Fix:
- SPF:   v=spf1 -all
- DMARC: v=DMARC1; p=reject
- DKIM:  configure signing

— Shadow Red Team | Authorized Assessment
"""

    msg = MIMEMultipart("alternative")
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg["X-Mailer"] = "Shadow-RedTeam/2.0"
    msg.attach(MIMEText(body, "plain"))

    try:
        print(f"  From  : {C.YELLOW}{from_addr}{C.RESET}")
        print(f"  To    : {C.YELLOW}{to_addr}{C.RESET}")

        if relay_user and relay_pass:
            print(f"  Mode  : {C.CYAN}Gmail Relay — {relay_user}{C.RESET}\n")
            server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
            server.ehlo()
            server.starttls()
            server.login(relay_user, relay_pass)
            server.sendmail(from_addr, [to_addr], msg.as_string())
            server.quit()
        else:
            print(f"  Mode  : {C.CYAN}Local SMTP {smtp_host}:{smtp_port}{C.RESET}\n")
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.sendmail(from_addr, [to_addr], msg.as_string())
            server.quit()

        print(f"  {C.GREEN}{C.BOLD}✅ Email sent!{C.RESET}")
        print(f"  {C.CYAN}Check inbox: {to_addr}{C.RESET}")
        return True

    except smtplib.SMTPAuthenticationError:
        print(f"  {C.RED}❌ Auth failed — check App Password{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}❌ {e}{C.RESET}")
    return False


def generate_report(domain, results, vulnerable, sent=False, from_addr=None, to_addr=None):
    import os
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M')
    fname = f"reports/spoof_{domain}_{ts}.md"
    with open(fname, 'w') as f:
        f.write(f"""# Email Spoofing Report — {domain}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

| Record | Status |
|--------|--------|
| SPF    | {results.get('spf')} |
| DMARC  | {results.get('dmarc')} |
| DKIM   | {results.get('dkim')} |

**Verdict:** {'🚨 VULNERABLE' if vulnerable else '✅ Protected'}

**PoC:** {'✅ Email sent from `' + str(from_addr) + '` to `' + str(to_addr) + '`' if sent else 'Not sent'}

*Shadow Red Team — Authorized Assessment*
""")
    print(f"\n  {C.GREEN}📄 Report: {fname}{C.RESET}")


def main():
    p = argparse.ArgumentParser(description='Shadow Email Spoofing Tester v2.0')
    p.add_argument('--domain',     required=True)
    p.add_argument('--from',       dest='from_addr')
    p.add_argument('--to',         dest='to_addr')
    p.add_argument('--subject')
    p.add_argument('--relay-user', help='Gmail address (relay)')
    p.add_argument('--relay-pass', help='Gmail App Password')
    p.add_argument('--smtp-host',  default='127.0.0.1')
    p.add_argument('--smtp-port',  default=2525, type=int)
    p.add_argument('--send',       action='store_true')
    args = p.parse_args()

    print(f"\n{C.CYAN}{C.BOLD}Shadow Email Spoofing Tester v2.0{C.RESET}")
    print(f"{C.YELLOW}Authorized penetration testing only{C.RESET}")

    results, vulnerable = check_domain(args.domain)

    sent = False
    if args.send:
        if not args.from_addr or not args.to_addr:
            print(f"  {C.RED}❌ --from and --to required{C.RESET}")
            sys.exit(1)
        sent = send_spoof_email(
            args.from_addr, args.to_addr, args.domain,
            args.subject, None,
            args.relay_user, args.relay_pass,
            args.smtp_host, args.smtp_port
        )

    generate_report(args.domain, results, vulnerable, sent, args.from_addr, args.to_addr)

if __name__ == "__main__":
    main()
