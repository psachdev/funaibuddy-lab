# funaibuddy-lab

Run your own scripts from a Claude chat, on a small server you rent, without
handing Claude the keys to that server.

You get a **custom Claude connector** (a small program on your server that
Claude can talk to) offering a **fixed menu of named "flows"**. A flow is one
command you wrote down in advance, such as "run the daily check" or "run the
tests". Claude can pick from the menu. It cannot run anything that is not on it.

This repository powers the [Agentic AI series on funaibuddy.com](https://funaibuddy.com/agentic-ai/),
where the first project on the menu is the
[Thesis Drift Monitor](https://github.com/psachdev/thesis-drift-monitor).
Swap in your own project by editing one file.

```
You, anywhere          Anthropic's cloud            Your server (about $6 a month)
┌──────────────┐      ┌────────────────┐      ┌───────────────────────────────────────┐
│ Claude chat  │ ───▶ │ Claude         │ ───▶ │ firewall: Anthropic addresses only    │
│ (phone, any  │      │ calls your     │      │ Caddy: HTTPS certificate              │
│  browser)    │ ◀─── │ connector      │ ◀─── │ connector: checks the secret token,   │
└──────────────┘      └────────────────┘      │   runs ONE named flow, hides secrets  │
                                              │ your project + its private keys       │
                                              └───────────────────────────────────────┘
```

## What it will and will not do

| It will | It will not |
|---|---|
| Run a flow from `flows.yaml`, with checked parameters | Run a free-form command line |
| Run flows on a schedule (for example every day at 11:00) | Change your code (code changes go through GitHub) |
| Show the result of the last run, and read project text files | Show secrets: keys are scrubbed from every output |
| Keep a log of every run | Read folders you mark private (for example paid research) |

## Set up a fresh server (about five minutes)

You need: an Ubuntu 24.04 server, a domain name you control, and a paid or free
Claude account (custom connectors work on every plan).

1. **Point a name at the server.** Add a DNS "A" record, for example
   `lab.example.com` → your server's address.
2. **Open the server's console** (your host's browser console is enough) and run:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/psachdev/funaibuddy-lab/main/setup/bootstrap.sh | bash
   ```

   It asks for your domain, a connector token (press Enter and it makes one),
   and the secrets your project needs. Secrets are typed on the server and stay there.
3. **Add the connector in Claude:** Settings → Connectors → Add custom connector.
   - Address: `https://lab.example.com/mcp`
   - Authentication: **No sign in**
   - Request header: `Authorization` = `Bearer <your connector token>`
4. **Try it.** In a chat, ask: *"Use my lab connector to list the flows."*

Server destroyed, or found a better deal? Repeat the four steps on the new one.
Three things are never in this repository and must be supplied again: the
connector token, your project's keys, and any private files your project keeps
out of git.

## Add your own project

Edit `/srv/lab/flows.yaml` on the server (start from
[`flows.example.yaml`](flows.example.yaml)), then:

```bash
lab check            # is the file valid?
lab secrets myproject
lab project-setup myproject
lab restart
lab schedules
```

## Everyday upkeep

`lab status`, `lab doctor`, `lab logs`, `lab audit`, `lab update`,
`lab rotate-token`. Run `lab help` for the full list. There is also a
[Claude skill](skill/SKILL.md) that teaches any Claude chat how to use and
look after the lab.

## How it is put together

See [docs/architecture.md](docs/architecture.md) for the design and
[docs/security.md](docs/security.md) for exactly what protects what, and what
does not.

## Layout

| Folder | What is in it |
|---|---|
| `connector/` | The connector program (Python) and its tests |
| `setup/` | The one-command setup script |
| `maintenance/` | The `lab` upkeep command |
| `skill/` | A Claude skill for using and maintaining the lab |
| `docs/` | Architecture and security notes |

## License

MIT. Not affiliated with Anthropic. Nothing here is investment advice.
