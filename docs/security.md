# Security notes

Read this before trusting the lab with a key that costs money.

## Layers

| Layer | Stops |
|---|---|
| Firewall (ufw): port 443 open only to Anthropic's published range `160.79.104.0/21`; port 80 open for certificate renewal only; everything else closed | Scanners and strangers reaching the connector at all |
| Remote login (SSH): passwords disabled. Either open for one public key you supply (rate-limited), or closed completely | Password guessing. If you close it completely, your host's browser console is the only emergency door, so confirm it works first |
| Caddy repeats the address check and answers 404 to anyone else | A firewall mistake exposing the connector |
| Secret token in the `Authorization` header, compared in constant time, 404 on failure | Another Anthropic customer who learns your address |
| Host-name check on every request | A class of browser trick called DNS rebinding |
| Fixed flow menu, parameters matched against patterns, no shell | Command injection and "run anything" misuse |
| Secrets passed by environment, scrubbed from output and file reads | A key being printed back into a chat |
| File reads fenced to the project folder; `.env`, key files, `.git` and your private folders blocked; symbolic links resolved first | Reading secrets or paid research through the file tool |
| Container runs as an unprivileged user, read-only system, no extra capabilities, memory and process limits | A bug in a script damaging the server |
| One run at a time per project, hard time limit per flow | Runaway or overlapping jobs |
| Audit log of every run; automatic security updates | Not noticing what happened; known holes staying open |

## Knowing if something is wrong

Ask Claude for the **security report** (the connector's `security_report` tool). It covers the
last 24 hours by default:

- every flow run, and whether it came from chat or from the server's own timer
- requests refused at the door, split into "no token" (routine internet noise) and
  "wrong token" (someone guessing)
- remote logins to the server, firewall state, and whether `flows.yaml` still matches the
  version you last approved with `lab restart`

The server writes its part hourly (`lab security-snapshot`). The report ends with an
`unusual` list; an empty list means nothing needs attention. It cannot tell your own runs
from runs made by someone holding your real token, so glance at the run list too.

Rotate the connector token every 90 days, or at once if it may have leaked:
`lab rotate-token`, then paste the new value into Claude's connector settings.

## What it does not protect against

- **Your Claude account.** Whoever controls your Claude account can run your
  flows. Use a strong password and two-step login there.
- **Your hosting control panel.** Whoever signs in there can open the console
  or wipe the server. Use a unique password and two-step login if offered.
- **A flow that leaks on purpose.** Scrubbing removes exact secret values. A
  script that printed a key backwards would get past it. Only put scripts you
  trust on the menu.
- **Your hosting company.** They can read the disk. Do not store anything you
  could not bear them seeing.
- **Spending.** A flow that calls a paid AI service spends real money each time
  it runs. Set a spending limit with that service.

## If something looks wrong

1. `lab rotate-token` — the old token stops working at once.
2. Replace the project keys at their source (for example the DeepSeek
   dashboard), then `lab secrets <project>`.
3. `lab audit 100` — see what ran.
4. If in doubt, rebuild: reinstall Ubuntu from your host's panel and run the
   setup command again.

## Changing Anthropic's address range

If Anthropic publishes a new range, edit `LAB_ALLOWED_IPS` in
`/etc/funaibuddy-lab/lab.env` (space-separated ranges inside the quotes) and
run the setup command again. Current ranges:
<https://platform.claude.com/docs/en/api/ip-addresses>
