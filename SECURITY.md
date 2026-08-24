# Security Policy

## Intended use

Tblue is built for scanning websites and web applications that you own or have explicit written permission to test. Running this tool against sites you do not own is illegal under computer fraud laws in most countries, regardless of intent or purpose.

## What this tool does and does not do

Tblue is a passive, read-only scanner. It looks at what your site sends back and flags things that do not match security best practices. It does not:

- Exploit any vulnerability it finds
- Attempt to log in or bypass authentication
- Send denial-of-service requests
- Try to evade firewalls or WAFs
- Generate or send attack payloads of any kind

## Reporting a vulnerability in Tblue itself

If you find a security issue in Tblue's own code, please do not open a public GitHub issue. Use GitHub's private vulnerability reporting at https://github.com/taylannuhogluofficial-png/Tblue/security/advisories/new, or email destek@turnayz.com directly so the issue can be fixed before it is publicly disclosed.

Include in your report:
- What the vulnerability is
- How to reproduce it
- What the potential impact could be

We aim to respond within 72 hours and resolve confirmed issues within 14 days.

## Your responsibilities as a user

By using Tblue you agree to:

- Only scan sites you own or have written permission to scan
- Not use Tblue as part of any unauthorized access attempt
- Not redistribute Tblue with malicious modifications added
