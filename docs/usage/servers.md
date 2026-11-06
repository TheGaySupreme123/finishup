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
| Local port | `finishup server add NAME https://127.0.0.1:PORT` (or `https://[::1]:PORT`, or `--port PORT`) | A FinishUP served over HTTPS on a port of this computer. It is treated like a web server, because a port can forward anywhere. |
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
is refused. FinishUP checks the certificate chain strictly: the certificate authority must be marked
for signing certificates (key usage `keyCertSign`). A home-made authority created without that
mark is refused as `remote_identity_changed`; recreate it with the mark, or use `--tls-pin`.

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
or choose a server on another machine, a port or the web. It checks when you add or choose the
server, not on every connection: changing the policy to zero-network later does not stop a server
you already chose. To stop using it, run `finishup server use local`, then restart open agent
sessions. FinishUP also refuses to add or choose such a server while the FinishUP set up
on this computer cannot tell it its policy, because its service is stopped or locked: start it
with `finishup service start`, unlock it if needed, and try again. A computer whose own FinishUP
was never set up has no privacy policy of its own and can use a server; the server's policy then
governs your work.

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
in use, its kind, whether it is reachable, both FinishUP releases, whether its vault is ready,
whether a key is stored and where (never the key itself), and the folders outside your projects
it may read on this computer (see below; `status --json` does not list them). The key's scope is set by the server's
operator and is not shown here. `test` connects, measures the round trip
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

## Let a server read a folder outside your project

A server on another machine, a port or the web reads your project folder through the workspace
agent (below). Outside your project folder it reads nothing on this computer unless you let it,
one folder at a time:

```text
finishup server folders add devbox /srv/team-specs
finishup server folders list devbox
finishup server folders remove devbox /srv/team-specs
```

`add` shows you which server may then read which folder, and what a server that does not follow
FinishUP's rules could read and list there, and asks you to type the server's name, in a terminal
you are typing in; an agent cannot do this. Give the folder's full path, starting with `/`. It
must exist, with no link on the way and no hidden or system folder in it (on macOS, give
`/private/tmp/...` rather than `/tmp/...`). Your home folder, a folder that holds it, and its
private folders such as `Library` cannot be added: add the folder inside it that you mean. A
server may read up to 32 such folders.

Once a folder is added, that server's checks and reviews may read files beneath it: input files a
task names there, files its reviewer asks to read there, and test files your agent declared
there. Hidden and credential-named files are never read and links are never followed. Input files
are read only where both sides allow it: beneath a folder you added here and beneath a folder the
server's own privacy policy lets it read task inputs from. Adding a folder inside one the server's
policy names lets it read that folder alone.

`remove` stops it at once; `remove NAME --all` removes every folder for that server, and also
clears a list FinishUP can no longer read (FinishUP then lets the server read no folder at all).
`list` and `server status` show the folders. The list stays on this computer and is never sent to
the server, and it belongs to that server alone: switching to another server does not change what
a connection already open to this one may read. Removing the server removes its list too. A server
on this computer does not use this list: there, the privacy settings decide which folders a review
may read (`finishup privacy input-roots`).

When a task names a file in a folder that the server's privacy policy covers but you have not
added for that server here, the workspace agent refuses to read it, and the check reports
`workspace_agent_refused`: the server then checks without seeing your change, rather than without
the file and without saying so. Add the folder with `server folders add` if you mean that server
to read it. A file the reviewer asks for, or a test your agent declared, in a folder you have not
added is skipped without a message; if a review seems to miss one, run `finishup server folders
list NAME` to see what that server may read.

## What leaves this computer

When you use a server on another machine, a port or the web, these travel to it:

- your agents' FinishUP calls and their results: task statements, published work, evidence,
  checks, responses and receipts;
- hook observations, under the observation consent you gave;
- a fingerprint of your project folder (a keyed digest, not its path);
- what the server asks your workspace agent for (below): the change since the task started,
  facts about files the task names, files the reviewer asks to read, task input files, declared
  test files, observation checks and the results of checks you approved — from your project
  folder and from the folders outside it that you let that server read, each within the same size
  limits FinishUP uses on one computer.

These do not leave: your project folder's full path, your API key, your vault passphrase, and
the secure unlock and consent prompts, which only ever run on the server's own machine.

Whether anything is then sent for AI-powered review is decided by the server's own privacy policy
and repository permissions, exactly as on one computer. Receipts and task status from a server on
another machine end with a line saying that workspace evidence was read on your computer by the
FinishUP workspace agent and attested over the connection, and a line naming the FinishUP service
that answered by its id (such as `svc_…`) and how this computer reached it (for example `ssh` or
`https`). This holds in the `finishup` command, in what your agent reads, and in the terminal
interface; JSON output does not carry these lines.

## The workspace agent

FinishUP checks your agent's work against the actual files: what changed since the task started,
the files a reviewer asks to see, the inputs the task names, and the checks you approved. On one
computer the FinishUP service reads them itself. A server on another machine cannot see your
files, so a small part of FinishUP on your computer — the **workspace agent** — answers the
server's questions about them.

The workspace agent answers only a fixed list of questions, only about the project folder your
session is working in and the folders outside it that you let that server read (`finishup server
folders`), and only within the usual size limits. It runs only check commands from your project's
approved check list. It reads files with the same safety checks FinishUP uses on one computer,
returns a file of your project only when Git confirms that the file is not ignored, and never
reads FinishUP's own folders on this computer — including the vault and settings of your everyday
FinishUP — whichever server you use.

Where Git cannot answer for a file, the workspace agent does not return it. This happens in a
linked Git worktree, inside a Git submodule, and in a project folder that is not a Git repository.
A reviewer cannot read such a file on one computer either. A test file your agent declared that
Git ignores, or that lies in such a place, is not offered to the server's reviewer, although
FinishUP on one computer offers it.

The workspace agent cannot tell an honest question from any other. A server that does not follow
FinishUP's own rules could ask it for any file in your project folder, or in a folder you let that
server read, that passes these safety checks, not only the files a task names. It could also see
the names of the files in those folders, ignored ones included, and learn whether a file exists
elsewhere on this computer, and its size and dates, but never its contents.
Use a server you trust with your project, and let it read only folders you would let it see.

It is its own small process on your computer, `finishup agent run` (see "How your computer reaches
the server" below), which your FinishUP tools and hooks start when they first use the server from a
project. It answers while a call is running and keeps answering after the call returns, because
some work — a longer review, an approved check — happens later. If nothing on your computer
answers in time, the receipt names exactly what could not be read; a check never passes because a
read was missing.

## Preparing the server

- Install the **same FinishUP release** on both machines. A server running a different release is
  refused with a message naming both releases; upgrade one of them.
- Set FinishUP up **on the server first**, in a terminal there: `finishup setup` creates its vault,
  privacy policy and any AI-powered review provider. Those settings live on the server.
- Let the server's FinishUP restart **without you**. Setup's default keeps an unlock secret in the
  server's credential store or in a file only you can read, so a restarted service comes back
  ready. A vault you unlock with a passphrase you chose stays locked after every restart until you
  unlock it on the server.
- With that same unlock secret, the server's FinishUP also **re-opens by itself** after it locked
  itself (after a while without use, or when the server's session locks or the machine sleeps):
  the next request from your computer re-opens it. Locking it yourself, or the server's session
  locking, takes priority over a re-open under way. A re-open that cannot finish within 30
  seconds stops and leaves the server locked, and a later request tries again. If the reason is
  that the server's credential store does not answer, FinishUP waits for that answer rather than
  asking again, and until it comes, requests are refused as locked straight away. After a
  re-open, FinishUP also tidies the stored unlock secret in that credential store. The tidy-up
  never holds the re-open up or locks the server again; if the store stops answering it, the next
  re-open waits for that answer in the same way. A re-open part-way through preparing FinishUP's
  storage finishes that step before it stops, so a lock can take a moment longer then.
- Those limits hold for a vault that FinishUP opens with a stored unlock secret for its passphrase
  (`finishup service status --json` shows `"vault_mode": "passphrase"`). If the vault key itself
  is kept in the server's credential store (`"vault_mode": "os_keyring"`) and that store stops
  answering, the whole service waits for it: nothing, locking included, takes effect until it
  answers.
- On **Linux**, a service started from an SSH login loses its connection folder when you log out
  unless lingering is on for your account (`loginctl enable-linger`), or FinishUP runs in its own
  folder on the server. `finishup service endpoint --json`, run on the server, reports both.

## Turn on the server's network API

Your computer reaches a FinishUP server through the server's own network API. The server's owner
turns it on, on the server, by adding a `[network]` section to its FinishUP settings file
(`config.toml`) and restarting its FinishUP service. Without that section the server opens no
network connection at all.

For an **SSH** server, one line is enough: it serves the API on a socket only you can open, which
your SSH connection reaches. No API key is involved; SSH already proves it is you.

```toml
[network]
api_socket = true
```

For a **web** or **port** server, list the addresses to listen on and the server's certificate and
private key. FinishUP refuses to listen without TLS, except on this machine's loopback address
when you put a TLS proxy in front of it and say so with `allow_plain_loopback = true`. The key file
must be readable only by you.

```toml
[network]
listen = ["0.0.0.0:8443"]
tls_cert = "/etc/finishup/server.pem"
tls_key = "/etc/finishup/server-key.pem"
```

Then, on the server, create a key for each computer or person and give it to them:

```text
finishup service api-key create --label laptop --scope agent
finishup service api-key create --label admin --scope operator --output-file admin.key
finishup service api-key list
finishup service api-key revoke 3f9a1c0b2d4e
```

The key is shown once; the server keeps only a scrambled form of it. An `agent` key allows what
agents need; an `operator` key also allows management reads and policy tightening. Nothing that
stops the server, backs it up, restores or migrates it, or unlocks its vault can be done with any
key. To replace a key without losing access to existing tasks, create the new one with
`--rotate OLD_KEY_ID`, sign in with it, then revoke the old one. `finishup service endpoint --json`
on the server shows what is turned on.

## How your computer reaches the server

FinishUP's tools, hooks, the `finishup` command and the terminal interface each talk to the server
directly, over HTTPS for a web or port server and through one shared SSH connection for an SSH
server. That SSH connection starts when first needed and closes after 15 minutes without use;
`finishup server connect` starts it now and `disconnect` closes it.

The workspace agent is a small FinishUP process on your computer, `finishup agent run`, that
starts when your sessions first use a server on another machine and stops 15 minutes after the
last one ends. It asks the server for work rather than waiting for the server to call in, so it
works through firewalls and proxies that allow ordinary HTTPS. It also delivers, in the
background, the observations your hooks recorded but could not deliver themselves, each with this
computer's observation settings. `finishup server disconnect` stops it too.

When the server cannot be reached, FinishUP's tools, hooks, the `finishup` command and the
terminal interface name what went wrong with one of the `remote_…` reasons below and its next
step; they never tell you to start or unlock a FinishUP service on this computer, because none
serves that server.

On a web or port server, each FinishUP process on your computer reads your API key from your
credential store when it connects. Software running as you can read that store too, as it can
read FinishUP's own unlock secret; nothing an agent can call shows or changes the key.

## Things that run on the server

Vault setup and unlock, passphrase changes, privacy choices, AI-powered review providers,
backup, restore and migration belong to the server. On this computer those commands stop with
`requires_server_host`.

Observation settings stay on this computer. Your hooks run here, so the observation consent you
give, the content you allow, the checks you approve and the observations waiting to be delivered
all live here, and `finishup observe …` changes them here whichever server you use. Each
observation this computer delivers carries those settings with it; the server accepts them as
your computer's own statement and does not check them itself. Receipts of such a task say so in
one more line. With a server elsewhere, `finishup observe drain` delivers one project's waiting
observations at a time: the one you name with `--workspace`, or the folder you run it in.

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
| `remote_unreachable` | The server could not be reached, so nothing was sent. | Run `finishup server test`. |
| `request_timeout` | The request reached the server, or may have, but its answer was lost on the way back. It may have been recorded. | Follow the shown continuation: it repeats the request safely under its original identity. |
| `remote_auth_failed` | The server did not accept you, or cannot check keys until its operator repairs its key file. | SSH: load your key (`ssh-add`) or check your SSH configuration. Web: run `finishup server login NAME`, or ask the server's operator. |
| `remote_identity_changed` | The server's host key or certificate is not the one you confirmed. | Confirm the server's identity another way, then remove and add the server again. |
| `remote_service_not_running` | The server machine answered, but its FinishUP service is not running. | SSH: `ssh -t <server> finishup service start`. Web: ask the server's operator. |
| `remote_incompatible` | The two machines run different FinishUP releases. | Install the same release on both. |
| `target_reauthorization_required` | This release shows a newer disclosure of what leaves your computer than the one you confirmed for that server, so nothing is sent to it. | Run `finishup server use NAME` in your own terminal and confirm again. |
| `vault_locked` | The server's vault is locked. | SSH: `ssh -t <server> finishup service unlock`. Web: the operator unlocks it on the server. |
| `requires_server_host` | That command belongs to the server. | Run it on the server, as shown above. |
| `method_forbidden` | The API key's scope does not allow that call. | Use an `operator` key for management commands. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer. | Run `finishup server use local`, then remove the server and add it again. |
| `selection_invalid` | The saved server choice is damaged, or names a server whose folder on this computer is missing or unsafe. `finishup server` commands say this instead of `isolation_root_invalid`. | Run `finishup server use local`; it clears the choice even when it cannot be read. |
| `target_root_is_remote` | Something tried to start a FinishUP service on this computer for a server that runs elsewhere. FinishUP refuses and starts nothing. | Start it on the server instead, or run `finishup server use local` to use this computer's FinishUP. |
| `workspace_agent_unavailable` | The server needed something from your project, and nothing on this computer gave a usable answer: not connected, too slow, or failed. A receipt says so where it could not see your change. | Use FinishUP from that project again (any FinishUP tool or hook starts the workspace agent) and check again; the receipt names what was not read. |
| `workspace_agent_refused` | The workspace agent refused a request: outside your project, outside the folders you admitted, or a check command not on the check list you approved and trusted on this computer. A receipt says so where the refusal kept the server from seeing your change. | Nothing to repair unless you meant to admit that folder or trust that check list. |
| `workspace_ref_not_portable` | A task on a server elsewhere was started with a full folder path or another value the server cannot use. | FinishUP's own tools send the right value; a hand-written client must send the workspace handle the server gave it, or name no project. |
| `workspace_binding_conflict` | A request named the project in a form its connection cannot use: a server-elsewhere `client:` handle sent to this computer's FinishUP, or a folder path and a server-elsewhere claim together. | Name the project by its folder path through FinishUP's own tools; a hand-written client must not send a `client:` handle to a local server. |
| `folder_invalid` | `server folders add` was given a folder it cannot admit: not a full path, missing, reached through a link, hidden, a system folder, or your home folder, a folder that holds it or one of its private folders. | Give the full path of the existing folder you mean, inside your home folder if it is there. |
| `folders_record_invalid`, `folders_record_unsafe` | The list of folders a server may read on this computer is damaged or not private to you, so that server reads no folder outside your projects. | Run `finishup server folders remove NAME --all`, then add the folders again. |

In the terminal interface, the header shows which server is in use, and `/server` lists your
servers and can switch between them with the same confirmation. Its status view lists the folders
the server may read, and it prints the `finishup server folders` commands for you to run in your
shell.
