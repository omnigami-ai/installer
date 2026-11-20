# omnigami

The installer for [omnigami](https://omnigami.ai) skills: launch films, decks and images your coding agent makes
from your product's real screens.

```sh
npx omnigami login
npx omnigami install product-film
```

`login` prints a short code and opens omnigami.ai in your browser. Sign in, check that the code matches, and approve.
Approve only a code you just started yourself in your own terminal. Approval lasts 30 days and can be revoked any time
on [your account page](https://omnigami.ai/account).

`install` puts the skill where your agent reads skills, then you ask your agent to use it. Free skills need a free
account; Pro skills need the purchase or pass on the same account.

## Commands

| Command | What it does |
| --- | --- |
| `omnigami login` | Approve this computer in your browser |
| `omnigami status` | Whether this computer is approved, and until when |
| `omnigami list` | The skills your account can install |
| `omnigami install <skill>` | Install a skill (`--agent`, `--target`, `--force`) |
| `omnigami update [<skill>]` | Update one installed skill, or all of them |
| `omnigami logout` | Revoke this computer's approval |

Add `--json` to any command for output an agent can read. `login --json` prints one line with the address and code to
show the person, then one line when they have approved.

## Where skills go

| `--agent` | Folder |
| --- | --- |
| `claude-code` | `~/.claude/skills` |
| `codex` or `shared` (the default) | `~/.agents/skills` |
| `cursor` | `~/.cursor/skills` |
| `gemini-cli` | `~/.gemini/skills` |

`--target <folder>` chooses another parent folder. If the skill is already there, `--force` replaces it and keeps a
backup beside it. `update` never overwrites a skill you have edited: it stops and tells you.

## What it checks

Every release is signed by omnigami. Before anything is written, the installer checks the signature against the key
in `trusted-keys.json`, then the archive's size and SHA-256, and refuses archives with links or paths outside the
skill's folder. It runs no scripts, sends no telemetry and never updates itself.

Your approval is stored in the macOS Keychain, the Linux Secret Service or the Windows credential vault, or in a file
only you can read if none is available. It is never printed and never passed on a command line.

Requires Node 20 or later. Tested on macOS; Linux and Windows use the same code paths and have not yet had the same
testing: please [write to us](https://omnigami.ai/contact) if something fails.

## For agents

Run `npx omnigami login --json`, show the person the address and code from the first line, and wait for the second.
Never approve for them. Then `npx omnigami install <skill> --agent <your agent> --json`.

MIT license. omnigami is a product of Auberon LLC and is not affiliated with Anthropic.
