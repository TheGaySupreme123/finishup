# FinishUP servers

By default FinishUP runs one service on your own computer, and your agents, the `finishup`
command and the terminal interface all use it. A **server** lets them use a different FinishUP
service instead:

- another FinishUP on this computer, with its own tasks, settings and vault;
- a FinishUP reached on a port of this computer;
- a FinishUP on another machine you reach over SSH;
- a FinishUP hosted on the web, reached over HTTPS with an address and an API key.

Nothing changes until you add a server and choose to use it. Without one, FinishUP behaves exactly
as it always has.

## Kinds of server

| Kind | Add it with | What it is |
|---|---|---|
| Local | `finishup server add NAME --local` | A second FinishUP on this computer, with its own tasks, vault and settings. It starts when something first needs it, like the default one. |
| Local port | `finishup server add NAME https://127.0.0.1:PORT` | A FinishUP served over HTTPS on a port of this computer. It is treated like a web server, because a port can forward anywhere. |
| SSH | `finishup server add NAME ssh://[user@]host[:port]` | A FinishUP on another machine that you log in to over SSH, as yourself. |
| Web (HTTPS) | `finishup server add NAME https://host[:port][/path]` | A FinishUP hosted on the web. You sign in to it with an API key. |

A name is up to 16 lowercase letters, digits and hyphens, starting with a letter or digit. `local`
is reserved: it always means the default FinishUP on this computer. FinishUP shows names and
addresses only in `finishup server list`, `status` and `test`; everywhere else, including messages
your agent can read, a server is named by a short id such as `t_1a2b3c4d`.

For an SSH server you can also give `--remote-root DIR` (the FinishUP folder on the server, when it
runs in its own folder there) and `--remote-launcher PATH` (the full path of `finishup` on the
server). For a web or port server, give the certificate authority that signed the server's
certificate with `--ca-file FILE`, or pin the certificate with `--tls-pin sha256:…`. Plain `http`
is refused.

## Add a server

```text
finishup server add lab --local
finishup server add devbox ssh://me@devbox.example
finishup server add team https://finishup.example.com --ca-file team-ca.pem
finishup server add bench https://127.0.0.1:8443 --tls-pin sha256:<64 hex digits>
```

A **local** server needs its own setup: select it (below) and run `finishup setup`, exactly as for a
first installation.

For every other kind, FinishUP first shows what will leave this computer (see
[What leaves this computer](#what-leaves-this-computer)) and asks you to type the server's name to
confirm. You do this yourself, in a terminal you are typing in. An agent cannot add or choose such
a server: there is no agent tool for it, and the command refuses to run without a terminal. If the
disclosure changes in a later release, FinishUP asks you to confirm again before using the server.

If your privacy policy forbids all network use (the zero-network setting), FinishUP refuses to add
or use a server on another machine, a port or the web.

## Sign in to a web server

```text
finishup server login team
finishup server login team --key-file team.key
finishup server logout team
```

`login` asks for the API key at a masked prompt. For automation, `--key-file` reads it once from a
file only you can read. FinishUP keeps the key in your system's credential store, or in a file only
you can read where no credential store is usable. It never puts the key in a command line, an
environment variable, a settings file, a log, a message your agent can read, or JSON output.
`logout` deletes it. The server's operator gives you the key; a key has a scope, and an `agent` key
allows what your agents need while an `operator` key also allows management reads such as privacy
status.

SSH servers need no FinishUP sign-in. Your SSH keys, `ssh-agent` and known hosts stay with SSH;
FinishUP stores no SSH key and never asks for an SSH password.

## Use a server

```text
finishup server use devbox
finishup server use local
```

`use NAME` makes every FinishUP client on this computer use that server: your agents' hooks and
FinishUP tools, the `finishup` command and the terminal interface. `use local` goes back to the
default FinishUP on this computer. Choosing a server on another machine, a port or the web asks for
the same typed confirmation as adding it.

Restart agent sessions that are already open. An open session's FinishUP tools keep the server
they started with, while its hooks follow the new choice at once.

Your agent hosts need nothing new: Claude Code, Codex and Cursor keep their existing connection and
follow your choice. A test copy of FinishUP that runs in its own folder is not affected by the
choice, and `server use` refuses while such a setting decides which FinishUP is used.

## Check a server

```text
finishup server list
finishup server status devbox
finishup server status --json
finishup server test devbox
```

`list` shows every server and which one is in use. `status` shows which setting chose the server
in use, its kind, whether it is reachable, both FinishUP releases, whether its vault is ready, the
key's scope and whether a key is stored (never the key). `test` connects, measures the round trip
and warns when it is slow enough that a startup check required by your agent setup would likely
time out.

## Connect and disconnect

```text
finishup server connect devbox
finishup server disconnect devbox
```

FinishUP connects on demand, so you rarely need these. `connect` gets the connection to a server
ready now and keeps it ready while you work; `disconnect` closes what `connect` opened. Neither
stops the FinishUP service on the server.

## Remove a server

```text
finishup server remove lab
finishup server remove devbox --select-local
```

`remove` disconnects, deletes the stored key and removes everything FinishUP kept on this computer
for that server. It refuses the server you are using unless you add `--select-local`, which
switches back to the default first. Removing a local server deletes its tasks and vault; removing
a server on another machine leaves that server untouched.

## What leaves this computer

When you use a server on another machine, a port or the web, these travel to it:

- your agents' FinishUP calls and their results: task statements, published work, evidence,
  checks, responses and receipts;
- hook observations, under the observation consent you gave;
- a fingerprint of your project folder (a keyed digest, not its path);
- what the server asks your workspace agent for (below): the change since the task started,
  facts about files the task names, files the reviewer asks to read, task input files, declared
  test files, observation checks and the results of checks you approved — each within the same
  size limits FinishUP uses on one computer.

These do not leave: your project folder's full path, your API key, your vault passphrase, and
the secure unlock and consent prompts, which only ever run on the server's own machine.

Whether anything is then sent for AI-powered review is decided by the server's own privacy policy
and repository permissions, exactly as on one computer. Receipts from a server on another machine
carry one extra line saying that workspace evidence was read on your computer by the FinishUP
workspace agent and attested over the connection.

## The workspace agent

FinishUP checks your agent's work against the actual files: what changed since the task started,
the files a reviewer asks to see, the inputs the task names, and the checks you approved. On one
computer the FinishUP service reads them itself. A server on another machine cannot see your
files, so a small part of FinishUP on your computer — the **workspace agent** — answers the
server's questions about them.

The workspace agent answers only a fixed list of questions, only about the project folder your
session is working in, only within the folders you admitted, and only within the usual size
limits. It runs only check commands from your project's approved check list. It reads files with
the same safety checks FinishUP uses on one computer.

It runs inside your FinishUP clients while they are connected to the server, and keeps running
after a call returns, because some work — a longer review, an approved check — happens later. If
nothing on your computer answers in time, the receipt names exactly what could not be read; a check
never passes because a read was missing.

## Preparing the server

- Install the **same FinishUP release** on both machines. A server running a different release is
  refused with a message naming both releases; upgrade one of them.
- Set FinishUP up **on the server first**, in a terminal there: `finishup setup` creates its vault,
  privacy policy and any AI-powered review provider. Those settings live on the server.
- Let the server's FinishUP restart **without you**. Setup's default keeps an unlock secret in the
  server's credential store or in a file only you can read, so a restarted service comes back
  ready. A vault you unlock with a passphrase you chose stays locked after every restart until you
  unlock it on the server.
- On **Linux**, a service started from an SSH login loses its connection folder when you log out
  unless lingering is on for your account (`loginctl enable-linger`), or FinishUP runs in its own
  folder on the server. `finishup service endpoint --json`, run on the server, reports both.

<!-- APPROACH-TOPOLOGY -->

## Things that run on the server

Vault setup and unlock, passphrase changes, privacy choices, AI-powered review providers,
observation settings, backup, restore and migration belong to the server. On this computer those
commands stop with `requires_server_host`.

For an SSH server you can run the service commands through SSH, from a terminal:

```text
ssh -t me@devbox.example finishup service unlock
ssh -t me@devbox.example finishup service status
```

For a web server, its operator runs them on the server machine.

## Troubleshooting

FinishUP never quietly falls back to the FinishUP on this computer when a server cannot be reached,
and it never queues work to send later: a call that could not reach the server says so and can be
repeated safely.

| You see | What it means | What to do |
|---|---|---|
| `remote_unreachable` | The server could not be reached. | Run `finishup server test`. |
| `remote_auth_failed` | The server did not accept you. | SSH: load your key (`ssh-add`) or check your SSH configuration. Web: run `finishup server login NAME`. |
| `remote_identity_changed` | The server's host key or certificate is not the one you confirmed. | Confirm the server's identity another way, then remove and add the server again. |
| `remote_service_not_running` | The server machine answered, but its FinishUP service is not running. | SSH: `ssh -t <server> finishup service start`. Web: ask the server's operator. |
| `remote_incompatible` | The two machines run different FinishUP releases. | Install the same release on both. |
| `vault_locked` | The server's vault is locked. | SSH: `ssh -t <server> finishup service unlock`. Web: the operator unlocks it on the server. |
| `requires_server_host` | That command belongs to the server. | Run it on the server, as shown above. |
| `method_forbidden` | The API key's scope does not allow that call. | Use an `operator` key for management commands. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer. | Run `finishup server use local`, then remove the server and add it again. |
| `target_root_is_remote` | Something tried to start a FinishUP service on this computer for a server that runs elsewhere. | Start it on the server instead. |
| `workspace_agent_unavailable` | The server needed something from your project, and nothing on this computer answered in time. | Keep the agent session open (or run `finishup server connect`) and check again; the receipt names what was not read. |
| `workspace_agent_refused` | The workspace agent refused a request: outside your project, outside the folders you admitted, or a check command not on your approved list. | Nothing to repair unless you meant to admit that folder or check. |
| `workspace_ref_not_portable` | A task on a server elsewhere was started with a full folder path. | FinishUP's own tools send the right value; a hand-written client must send the workspace handle the server gave it. |
| `workspace_binding_conflict` | A client sent two different ways of naming the project. | Report it as a bug. |

In the terminal interface, the header shows which server is in use, and `/server` lists your
servers and can switch between them with the same confirmation.
