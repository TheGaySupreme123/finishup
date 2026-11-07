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
| Local port | `finishup server add NAME https://127.0.0.1:PORT` (or `https://[::1]:PORT`, or `--port PORT`) | A FinishUP served over HTTPS on a port of this computer. You confirm it and sign in to it like a web server, because a port can forward anywhere. |
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
is refused. FinishUP checks certificates strictly: the authority's own certificate must be marked
for signing certificates (the key-usage extension that current tools add to an authority). An
older or hand-made authority without it is refused, and `server login` then reports
`remote_identity_changed`; make a new authority, or pin the server's certificate instead.

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
[What leaves this computer](#what-leaves-this-computer)), then asks what the server may read
outside your projects on this computer, its *mode* (see
[below](#choose-what-a-server-may-read-outside-your-project)), with one line for each choice:

```text
What may this server read outside your projects on this computer?
  local   what FinishUP on this computer would read there; choose it for a server you trust as you trust this computer
  listed  only folders you list for it with 'finishup server folders add'; nothing else there
You can change it later with 'finishup server folders mode devbox local' or 'finishup server folders mode devbox listed'.
Type local or listed:
```

Every kind of server, SSH, a port of this computer or the web, gets the same question and the same
two choices. Type `local` or `listed`; Enter alone does not choose. If you choose `local`,
FinishUP then shows what that lets the server read, including what a server that breaks
FinishUP's rules could read, the same notice `finishup server folders mode NAME local` shows.
Then type the server's name to confirm both. You do this yourself, in a terminal you are typing
in. An agent cannot add or choose such a server: there is no agent tool for it, and the command
refuses to run without a terminal. To answer the question up front, add `--outside-reads local`
or `--outside-reads listed`; you still see the notice for `local`, and still confirm with the
server's name. An official FinishUP service is not asked: it reads what FinishUP on this computer
would read. Add one without `--outside-reads`: an answer you give is kept as your own choice
rather than following FinishUP's list of official services. If the disclosure changes in a later
release, FinishUP asks you to confirm again before using the server. Once the server is added, FinishUP says which mode
it has and the one command that changes it. After that, nothing asks again: your agents' hooks
and FinishUP tools, the `finishup` command and the terminal interface all follow your choice.

If your privacy policy forbids all network use (the zero-network setting), FinishUP never uses a
server on another machine, a port or the web: it refuses to add or choose one. It also refuses
while the FinishUP set up on this computer cannot tell it its policy, because its service is
stopped or locked: start it with `finishup service start`, unlock it if needed, and try again. If
this computer last told FinishUP that the setting is on, the refusal says so, with when. A
computer whose own FinishUP was never set up has no privacy policy of its own and can use a
server; the server's policy then governs your work.

### Zero-network and a server elsewhere are never on together

While a server on another machine, a port or the web is chosen, a new FinishUP command does not
change this computer's privacy policy. `finishup privacy setup`, the other privacy settings,
`finishup ai` and the terminal interface's `/privacy` refuse to run (`requires_server_host`), and
`finishup privacy tighten` and `finishup privacy propose` change the chosen server's policy, not
this computer's, and say so (see [Whose privacy policy a command
changes](#whose-privacy-policy-a-command-changes)). To change this computer's policy, run
`finishup server use local` first.

FinishUP that was already working with this computer's own FinishUP when you chose the server can
still change this computer's policy: a terminal interface or menu that was open then, or a privacy
step or setup that was under way. If such a change would turn the zero-network setting on, FinishUP
asks you before it changes anything, and so it does when you approve a privacy decision that was
proposed before you chose the server and would turn the setting on: after you answer approve, and
before the approval is sent. It never switches for you.

In your own terminal it asks:

```text
This change makes this computer's FinishUP make no network connections, but the selected FinishUP server t_1a2b3c4d (ssh) is on another machine, reached over SSH.
FinishUP never uses a server elsewhere while this computer makes no network connections, so both cannot stay.
  1  Switch to this computer's everyday FinishUP and make this change
  2  Cancel this change and keep using the server t_1a2b3c4d (ssh)
Choose 1 or 2 (Enter cancels the change):
```

Choosing 1 is `finishup server use local`, then the change. Pressing Enter or Ctrl-C, or any
answer but 1, cancels the change: your privacy policy stays as it was and the server stays chosen.
Without your terminal to ask in (a script, a command asked for JSON, or a change your agent
relays), FinishUP refuses the change before making it and says why, with
`zero_network_remote_selected`: run `finishup server use local`, then make the change again.

Switching, whichever way you do it, also closes this computer's connection to that server, as
`finishup server disconnect` does. Work the server had already started for you, such as a review
still running, can then no longer read your files. As the connection closes it sends that server,
for at most 2 seconds, what your agents' hooks had already recorded for it; anything left stays on
this computer. Once this computer has reported the zero-network setting, nothing more is sent, not
even that last delivery. If the connection does not close in time, FinishUP still switches and tells
you to run `finishup server disconnect` with that server's name. After switching, restart open agent
sessions: they keep the server they started with until then. Choosing the server again needs the
setting turned off first.

Anything still pointed at a server elsewhere while this computer forbids all network use (an
agent session or hook started before the change, or a server you kept with an earlier release) is
refused before anything is sent to it, on every surface, with `zero_network_remote_selected` and
the same fix: `finishup server use local`, then restart open agent sessions. This check uses what
this computer last reported (below), so after an upgrade it starts once this computer's FinishUP
has reported its policy again. The connections FinishUP keeps open to that server, including the
one through which the server reads your project for its checks and reviews and the delivery of
what your hooks captured, are closed within about a second of this computer reporting the
setting, and nothing more is sent over them; a request already under way in that second may
still finish.

A command that acts on one server says what stands in the way of that server. For the chosen
server it is `zero_network_remote_selected`, fixed by `finishup server use local`. For a server
you added earlier but have not chosen, choosing this computer's FinishUP would change nothing:
`finishup server login`, `connect`, `test` and `status` for it say `zero_network_in_force`, with
when this computer last reported the setting, and the fix is to change this computer's privacy
policy with `finishup privacy setup` first. `finishup server status` and `test` then show "not
probed, nothing was sent" instead of probing it, and `test` never says the server did not answer.

### What this computer last reported

Only this computer's own FinishUP service can tell its privacy policy, and it is usually stopped or
locked while you use a server elsewhere. So FinishUP remembers what it last reported: whether the
zero-network setting was on, and when. It keeps this in a small file only you can read, beside
its list of servers and outside the vault, with no path, name or policy content in it. It is
updated whenever this computer's FinishUP reports its policy: when it checks a server you add or
choose, when you run `finishup privacy show` or the menu's privacy view, and after every privacy
change made here.

`finishup setup status --next`, `finishup server status` and `finishup server list`, the setup
summary, the menu and the terminal interface's header and `/server` say so while a server
elsewhere is chosen and the setting is on. They ask this computer's FinishUP first; when it
cannot answer, they say "This computer last reported, at <time>, that its privacy policy forbids
all network use" instead. `finishup server status --json` gives the same notice as its
`zero_network_selection` member: `policy_read` is `live` or `last_reported`, with
`last_reported_at` for the latter (null when there is nothing to say). If the saved server choice
cannot be read, FinishUP says that instead of guessing, and `finishup server use local` clears it.
It cannot tell then which server's connection to close: run `finishup server disconnect NAME` for
a server on another machine you were using.

If that file cannot be read (it was damaged, or its permissions changed), FinishUP treats it as no
record: nothing claims the setting from it, and the next report replaces it. Deleting FinishUP's
folders (see [Where your data lives](upgrading.md#where-your-data-lives)) removes it, and FinishUP
removes it itself once this computer's own FinishUP no longer exists.

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

`login` checks the key with the server before keeping it. If the server refuses the key, or runs
another FinishUP release, or its certificate is not the one you trusted, nothing is stored and
FinishUP says why and what to do. If the server cannot be reached right now, FinishUP stores the key
and says it is not verified yet: it is checked on the first connection, and `finishup server test
NAME` checks it as soon as the server is up.

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
whether a key is stored and where (never the key itself), and what it may read outside your
projects on this computer: its mode, why it has that mode, and the folders you listed for it
(see below; `status --json` includes them too). The key's scope is set by the server's operator
and is not shown here. `test` connects, measures the round trip
and warns when it is slow enough that a startup check required by your agent setup would likely
time out.

## Connect and disconnect

```text
finishup server connect devbox
finishup server disconnect devbox
```

FinishUP connects on demand, so you rarely need these. `connect` gets the connection to a server
ready now and keeps it ready while you work; `disconnect` closes what `connect` opened. Neither
stops the FinishUP service on the server. Choosing another server with `finishup server use`
closes the connection to a server on another machine, a port or the web that you leave, in the
same way.

## Remove a server

```text
finishup server remove lab
finishup server remove devbox --select-local
```

`remove` disconnects, deletes the stored key and removes everything FinishUP kept on this computer
for that server. It refuses the server you are using unless you add `--select-local`, which
switches back to the default first. If the connection to that server does not close in time,
`remove` changes nothing and asks you to run it again. Removing a local server deletes its tasks
and vault; removing a server on another machine leaves that server untouched.

## Choose what a server may read outside your project

A server on another machine, a port or the web reads your project folder through the workspace
agent (below). What it may read outside your project folder on this computer is up to you. Each
such server has one of two modes, the same two for every kind:

- **local**: it reads outside your project exactly as FinishUP on this computer would. The
  server's own privacy settings decide which folders it reads task inputs from, it also reads the
  files a task names beneath folders you list for it, and FinishUP's usual safety checks still
  apply.
- **listed**: it reads outside your project only beneath folders you list for it, one at a time.
  Inside your project it reads a test your agent declared only when Git does not ignore it.

You choose when you add the server (above). An official FinishUP service is in local mode without
being asked, because the official service gets the same access as FinishUP on this computer; no
official service exists yet. A server whose choice could not be saved is in listed mode until you
choose, and `list`, `server status` and `/server` show the two commands that choose. To change the
mode later:

```text
finishup server folders mode team local
finishup server folders mode devbox listed
finishup server folders list devbox
```

Choosing local shows you what that lets the server read, including what a server that does not
follow FinishUP's rules could read and list, and asks you to type the server's name, in a terminal
you are typing in; an agent cannot do this. Choose it only for a server you trust as you trust
FinishUP on this computer. For an official FinishUP service, already in local mode, it records
local as your own choice; where nothing can ask you, as in an agent's shell, FinishUP records
nothing and says so. Choosing listed needs no confirmation and is always the way back. Either
choice applies from the server's next read on this computer; a read already under way may still
finish. `list`, `server status` and `/server` show the mode and why the server has it: set by you,
an official FinishUP service, or not chosen yet.

### Let a server read a folder outside your project

To let a server read the files a task names in a folder outside your project on this computer,
list that folder for it, one folder at a time. In listed mode, the folders you list are all it
reads outside your project folder:

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
there. Hidden and credential-named files are never read and links are never followed. The input
files a task names there are read in either mode, even when the server's own privacy policy lets
it read task inputs from no folder at all: the folder you listed on this computer is enough, and
the list is never sent to the server. The server's privacy policy still decides whether a task's
files are read for review at all, and whether and how they may be sent for AI-powered review. In
local mode the server also reads task inputs beneath the folders its own privacy policy names, as
FinishUP on this computer would; in listed mode, adding a folder inside one the server's policy
names lets it read that folder alone. A file the reviewer asks to read later is offered only in
folders the server's own policy names; a task's files from a folder you listed reach the review
with the check.

`remove` applies from the server's next read on this computer; a read already under way may still
return files from that folder, and a review the server already prepared may still send what it
read there. `remove NAME --all` removes every folder for that server, and also
clears a list FinishUP can no longer read: FinishUP then lets the server read no folder at all,
in listed mode, until you choose local again. `list` and `server status` show the folders. You can
list folders while a server is in local mode too: the files a task names there are read then as
well, and in listed mode the folders are all it reads, as FinishUP says. The list and the mode stay on this computer and are never sent to the server, and they belong
to that server alone: switching to another server does not change what a connection already open
to this one may read. If FinishUP cannot read them (the file is damaged or not private to you),
the server reads no folder outside your projects, whatever mode you chose; `server status`,
`server folders list` and `/server` then say so, with the one repair, `finishup server folders
remove NAME --all` on this computer. Removing the server
removes them too. A server on this computer does not use them: there, the privacy settings decide
which folders a review may read (`finishup privacy input-roots`).

In listed mode, when a task names a file in a folder that the server's privacy policy covers but
you have not listed for that server here, the workspace agent leaves just that file unread: the
server still checks the rest of your work, your change included, and the receipt says how many
files it kept back, for example "2 task inputs and 1 declared test outside the folders this server
may read were kept back.", then both ways out. The same
line covers a test your agent declared outside those folders, and, in listed mode, a declared
test in your project that Git ignores (or cannot answer for, such as one in a linked worktree).
If you mean that server to read them, run one of these on this computer, in your own terminal,
then check again:

```text
finishup server folders add NAME FOLDER
finishup server folders mode NAME local
```

The first lists a folder outside your project, for the files there. The second, for a server you
trust as you trust FinishUP on this computer, switches it to local mode, which reads all of them.
For a declared test in your project that Git ignores, listing a folder does not help, not even
your project's own: switch the server to local mode, or stop Git ignoring the test. When a task
names a file in a folder that neither your list nor the server's privacy policy covers, the
receipt says `task_input_outside_not_admitted` instead: list its folder for that server with
`finishup server folders add NAME FOLDER` on this computer, in either mode, then check again. A
path a task mentions that does not exist costs nothing:
FinishUP reads nothing there, as FinishUP on this computer would. A file the reviewer asks to read
in a folder you have not listed reads as absent; it is almost always one the task named, so the
receipt line above already covers it, and `finishup server folders list NAME` shows what that
server may read. In local mode nothing of this is left out: the agent reads as FinishUP on this
computer would, declared tests that Git ignores included.

## What leaves this computer

When you use a server on another machine, a port or the web, these travel to it:

- your agents' FinishUP calls and their results: task statements, published work, evidence,
  checks, responses and receipts;
- hook observations, under the observation consent you gave;
- a fingerprint of your project folder (a keyed digest, not its path);
- what the server asks your workspace agent for (below): the change since the task started,
  facts about files the task names, files the reviewer asks to read, task input files, declared
  test files, observation checks and the results of checks you approved — from your project
  folder and from outside it as you chose for that server (its mode, above), each within the same
  size limits FinishUP uses on one computer.

These do not leave: your project folder's full path, your API key, your vault passphrase, and
the secure unlock and consent prompts, which only ever run on the server's own machine.

Whether anything is then sent for AI-powered review is decided by the server's own privacy policy
and repository permissions, exactly as on one computer. Receipts and task status from a server on
another machine end with a line saying that workspace evidence was read on your computer by the
FinishUP workspace agent and attested over the connection, and a line naming the FinishUP service
that answered by its id (such as `svc_…`) and how this computer reached it (for example `ssh` or
`https`). This holds in the `finishup` command, in what your agent reads, and in the terminal
interface; JSON output does not carry these lines. A text or markdown receipt says where the
evidence was read in its own workspace evidence section and never leaves that section out, even
when a long receipt has its other sections shortened to fit. When your agent receives a long
receipt in pages, every page names the service, and the receipt's workspace evidence section, on
one of those pages, is the only place it says where the evidence was read. A receipt is never
refused because the server cannot tell where the evidence was read. If the server cannot read the
record of how the task's session was opened, the receipt is still made and says so, in three
lines: what happened (that record could not be read from the server's ledger), why it matters
(FinishUP cannot confirm whether the task's workspace evidence was read on your computer), and
whether trying again can help. That last line depends on the cause, and says only what is true of
it:

- **The server could not read the record this time.** It hit a storage fault while it read the
  record, or while it loaded the record when it opened the task. This can pass. The receipt says
  what to do: run the receipt again, and if this persists, restart the server's FinishUP service
  with `finishup service restart` on the server host, then run the receipt again. Once the server
  can read that record again, asking for the same receipt shows where the evidence was read. If
  the receipt still says this after a restart, the storage fault was still there, and the receipt
  keeps saying so for as long as that lasts.
- **The server's stored copy of the record is missing or fails its integrity check.** Opening
  the task again reads the same copy, so running the receipt again or restarting the service will
  not read it, and the task's receipts keep saying so for as long as that copy is missing or
  fails the check.
- **The record was redacted, or erased.** It will not become readable again. The receipt says so,
  and that every receipt of that task will keep saying its provenance is unknown; running the
  receipt again or restarting the service will not change that.
- **The server does not have the record's key.** Running the receipt again or restarting the
  service will not read the record, and the task's receipts keep saying so while that key is
  unavailable.
- **The record is in a format the server's FinishUP version cannot decode.** Running the receipt
  again or restarting the service will not read it, and the task's receipts keep saying so until
  the server runs a FinishUP version that knows that format; then the record reads and the
  receipt shows where the evidence was read.

Only the first gives retry or restart advice; for the others neither helps, so they give none.

Every receipt format says this: a text or markdown receipt in its workspace evidence section, and a
receipt in JSON format in its `workspace_provenance` entry, which holds `status` `unknown`, a
`reason` that names the cause (`session_opening_unreadable` for the one that can pass;
`session_opening_copy_unverifiable`, `session_opening_redacted`, `session_opening_erased`,
`session_opening_key_unavailable` or `session_opening_format_unknown` for one that lasts), and the
same three lines. The `finishup` command and the terminal interface show that entry as the same
section, and it leads the first page of a long receipt your agent receives in pages. Such a receipt leaves out the line saying the
evidence was read on your computer, and still names the service.

## The workspace agent

FinishUP checks your agent's work against the actual files: what changed since the task started,
the files a reviewer asks to see, the inputs the task names, and the checks you approved. On one
computer the FinishUP service reads them itself. A server on another machine cannot see your
files, so a small part of FinishUP on your computer — the **workspace agent** — answers the
server's questions about them.

The workspace agent answers only a fixed list of questions, only about the project folder your
session is working in and, outside it, what you chose for that server (`finishup server folders`),
and only within the usual size limits. It runs only check commands from your project's
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
server read, that passes these safety checks, not only the files a task names. In local mode that
means any such file on this computer, as FinishUP on this computer could read. It could also see
the names of the files in those folders, ignored ones included, and learn whether a file exists
elsewhere on this computer, and its size and dates, but never its contents.
Use a server you trust with your project, choose local mode only for a server you trust as you
trust FinishUP on this computer, and otherwise list only folders you would let it see.

It runs inside your FinishUP clients while they are connected to the server: the FinishUP tools in
your agent, the CLI and the terminal interface answer for the project they are working in. Some
work happens after a call returns — a longer review, or an approved check after a hook saw a
command — so the connection helper (below) also keeps a workspace agent for each project folder you
used with that server, for 15 minutes after that folder was last used or until you disconnect
from that server or switch away from it, and delivers what your agent's hooks recorded there. If
nothing on your computer answers in time, the receipt names exactly what could not be read; a
check never passes because a read was missing.

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
  re-open waits for that answer in the same way. Changing the vault passphrase waits a few
  seconds for the tidy-up to finish. If the store still has not answered by then,
  `finishup service rotate-passphrase` stops with `credential_store_check_in_progress`: nothing
  changed, and you can try again in a moment. A re-open part-way through preparing FinishUP's
  storage finishes that step before it stops, so a lock can take a moment longer then.
- Those limits hold for a vault that FinishUP opens with a stored unlock secret for its passphrase
  (`finishup service status --json` shows `"vault_mode": "passphrase"`). If the vault key itself
  is kept in the server's credential store (`"vault_mode": "os_keyring"`) and that store stops
  answering, the whole service waits for it: nothing, locking included, takes effect until it
  answers.
- On **Linux**, a service started from an SSH login loses its connection folder when you log out
  unless lingering is on for your account (`loginctl enable-linger`), or FinishUP runs in its own
  folder on the server. `finishup service endpoint --json`, run on the server, reports both.

## How your computer reaches the server

For a server on another machine, FinishUP runs a small **connection helper** on your computer, one
per server. Your agent's hooks, the FinishUP tools in your agent, the CLI and the terminal
interface all talk to that helper exactly as they talk to FinishUP on your own computer. The
helper starts by itself when it is first needed, keeps the connection to the server open so each
call is quick, and stops after 15 minutes without use. `finishup server connect NAME` starts it
now and `finishup server disconnect NAME` stops it, and so does switching away from that server
with `finishup server use`; `finishup server status NAME` shows whether it is connected and, if
not, why.

**SSH servers.** The helper uses your own OpenSSH setup: your keys, your SSH agent, your
`~/.ssh/config` and your `known_hosts`. FinishUP never stores an SSH key and never asks for a
password. It keeps one SSH connection open and sends each request over it. When you add the
server, FinishUP asks the server once, over SSH, where its FinishUP service listens and which
`finishup` it runs; if your computer has not seen that server's host key before, SSH asks you to
confirm it then. If the server's FinishUP service has stopped while idle, the helper starts it
again for you.

**Web (HTTPS) servers.** On the server, its operator runs FinishUP's web gateway and gives you an
API key:

```text
finishup service gateway key create --label my-laptop --scope agent --output-file ~/my-laptop.key
finishup service gateway run --listen 0.0.0.0:8443 --tls-cert server.pem --tls-key server-key.pem
```

The key is shown only once (or written only to that new file, readable by its owner). If it
cannot be shown or written, FinishUP revokes it at once, because nobody holds it. If that revoke
fails too, the error names the key and the exact `finishup service gateway key revoke` command to
run, and the key stays active until you run it. Copy the key to your computer as a file only you
can read, then:

```text
finishup server add work https://finishup.example.com:8443 --ca-file ~/work-ca.pem
finishup server login work --key-file ~/work.key
finishup server use work
```

`server login` checks the key with the server before it stores it, and keeps it, not verified yet,
only while the server cannot be reached (see [Sign in](#sign-in-to-a-web-server)). Only the
connection helper reads the key afterwards; your agent and its tools never see it.

- **Key scopes.** An `agent` key allows what your agent's tools and hooks need: the six FinishUP
  operations and the service status. An `operator` key also allows project and review commands,
  privacy reads and tightening, and locking the service. Stopping the service, backup, restore,
  migration and integration changes are never possible over the web; run them on the server.
- **Other key commands.** `finishup service gateway key list` shows each key's id, label, scope,
  whether it is active, expired or revoked, and when it was last used, never the key itself. `finishup service gateway key revoke KEY_ID`
  stops a key at once, including connections already open with it. To replace a key, create the
  new one with `--rotate KEY_ID`, log your computers in with it, then revoke the old one.
- **Without your own certificate.** Behind a web server or proxy that handles TLS, run the gateway
  with `--behind-proxy --listen 127.0.0.1:PORT`; it then accepts plain connections from that
  machine only.


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

### Whose privacy policy a command changes

While a server on another machine, a port or the web is chosen, three things on this computer
change that server's privacy policy, not this computer's: `finishup privacy tighten`, `finishup
privacy propose`, and the privacy step of `finishup setup` (also when you run setup from `finishup
menu` or the terminal interface's first run). Each one says so before it sends anything and again
in its result, naming the server by its id and kind, never by the name you gave it:

```text
Privacy policy changes here apply to the selected FinishUP server t_1a2b3c4d (ssh), not to this computer's everyday FinishUP.
Changed the privacy policy of the FinishUP server t_1a2b3c4d (ssh); this computer's everyday FinishUP was not changed.
```

- **A change that sends more waits on the server.** It needs your decision, and that decision is
  made only on the machine that runs the server. FinishUP says the change waits there and has not
  taken effect yet, and names the proposal and how long it waits:

  ```text
  The change waits for a decision on the FinishUP server t_1a2b3c4d (ssh): its policy has not changed yet, because a trusted decision runs only on that server host. Run 'finishup privacy decide-policy ppr_…' on that host before 2026-11-06 22:40 UTC; after that it expires unchanged, and making the change again here proposes it anew.
  ```

  Run that exact command on the server's machine before the time shown (in UTC; a proposal waits
  about five minutes). `finishup privacy pending` lists disclosure decisions, not policy proposals,
  so use the id FinishUP printed. If it expires first, nothing changed: run `finishup setup` (or
  the command you used) here again for a new proposal. On this computer `finishup privacy
  decide-policy` stops with `requires_server_host` and names the server, and setup's privacy step
  leaves the change waiting instead of opening a decision here.
- **Setup's next steps.** With such a server chosen, `finishup --privacy` and `finishup --set` run
  only on the server's machine, so setup never points you at them here. After a change left
  waiting, its next step is the same `finishup privacy decide-policy` command with the proposal's
  id and time; otherwise it is to run `finishup setup` here again.
- **When a command fails.** If the server never confirmed a change, FinishUP says no change was
  confirmed; `finishup privacy show` shows the server's policy as it is now, and you can run the
  command again.
- **With `--json`.** `privacy tighten` and `privacy propose` print the same document as always, and
  the same sentences go to standard error. The setup summary names the server on its privacy line,
  and the terminal interface says it again once the privacy step returns, with the proposal's id
  and time when the change waits. Both name the server whose policy the step changed, even if you
  switched to this computer's own FinishUP while the step ran.

To change this computer's own policy instead, run `finishup server use local` first.

## Troubleshooting

FinishUP never quietly falls back to the FinishUP on this computer when a server cannot be reached,
and it never queues work to send later: a call that could not reach the server says so and can be
repeated safely.

| You see | What it means | What to do |
|---|---|---|
| `remote_unreachable` | The server could not be reached, or the certificate authority file given with `--ca-file` was moved, cannot be read or holds no certificate. | Run `finishup server test`. If you moved or replaced that file, put it back or add the server again with the new file. |
| `remote_auth_failed` | The server did not accept you. | SSH: load your key (`ssh-add`) or check your SSH configuration. Web: run `finishup server login NAME`. |
| `remote_identity_changed` | The server's host key or certificate is not the one you confirmed. | Confirm the server's identity another way, then remove and add the server again. |
| `remote_service_not_running` | The server machine answered, but its FinishUP service is not running. | SSH: `ssh -t <server> finishup service start`. Web: ask the server's operator. |
| `remote_incompatible` | The two machines run different FinishUP releases. | Install the same release on both. |
| `target_reauthorization_required` | This release shows a newer disclosure of what leaves your computer than the one you confirmed for that server, so nothing is sent to it. | Run `finishup server use NAME` in your own terminal and confirm again. |
| `vault_locked` | The server's vault is locked. | SSH: `ssh -t <server> finishup service unlock`. Web: the operator unlocks it on the server. |
| `requires_server_host` | That command belongs to the server. | Run it on the server, as shown above. |
| `method_forbidden` | The API key's scope does not allow that call. | Use an `operator` key for management commands. |
| `selection_overridden` | An isolation setting or a pinned test copy decides which FinishUP is used, so `server use` cannot. | Unset `FINISHUP_ISOLATED_ROOT`, or run the command from your everyday installation. |
| `isolation_root_invalid` | The server in use has a missing or unsafe folder on this computer. | Run `finishup server use local`, then remove the server and add it again. |
| `zero_network_remote_selected` | This computer forbids all network use, or last said so, and a server on another machine, a port or the web is chosen: nothing is sent to it, and a privacy change that would leave both on is refused when FinishUP cannot ask you. | Run `finishup server use local`, then restart open agent sessions, and make the change again if one was refused. |
| `zero_network_in_force` | This computer forbids all network use, or last said so (with when), so FinishUP adds, chooses, logs in to, connects to and probes no server on another machine, a port or the web. Nothing was sent. | Change this computer's privacy policy with `finishup privacy setup`, then run the command again. |
| `zero_network_selection_unreadable` | This computer forbids all network use, or last said so, and the saved server choice cannot be read, so FinishUP cannot tell whether a server elsewhere is still chosen. | Run `finishup server use local`; it clears the choice even when it cannot be read. Then restart open agent sessions. |
| `selection_invalid` | The saved server choice is damaged, or names a server whose folder on this computer is missing or unsafe. `finishup server` commands say this instead of `isolation_root_invalid`. | Run `finishup server use local`; it clears the choice even when it cannot be read. |
| `target_root_is_remote` | Something tried to start a FinishUP service on this computer for a server that runs elsewhere. FinishUP refuses and starts nothing. | Start it on the server instead, or run `finishup server use local` to use this computer's FinishUP. |
| `workspace_agent_unavailable` | The server needed something from your project, and nothing on this computer gave a usable answer: not connected, too slow, or failed. A receipt says so where it could not see your change. | On this computer: `finishup server status NAME` shows the connection, and `finishup server connect NAME` makes it again (or keep the agent session open); then check again. |
| `workspace_agent_refused` | The workspace agent refused a request it does not answer, which usually means the two computers run different FinishUP releases; or a check command that is not on the check list you approved and trusted on this computer. A receipt says so where the refusal kept the server from seeing your change. | Install the same release on both computers, run `finishup server connect NAME` on this computer, and check again. For a check command, review the project's check list and trust it on this computer, in the project folder: `finishup observe checks trust --policy-digest <digest>` (the digest `finishup observe checks preview` shows). |
| `outside_reads_not_listed` | In listed mode, the workspace agent left unread some files a task names, or tests your agent declared, outside the folders you listed for that server, or declared tests in your project that Git ignores. The receipt says how many of each. The rest of the work was checked. | On this computer, in your own terminal: `finishup server folders add NAME FOLDER` for a file outside your project, or, for a server you trust as you trust FinishUP on this computer, `finishup server folders mode NAME local`, the only command that helps for an ignored test in your project (or stop Git ignoring it). Then check again. |
| `workspace_ref_not_portable` | A task on a server elsewhere was started with a full folder path or another value the server cannot use. | FinishUP's own tools send the right value; a hand-written client must send the workspace handle the server gave it, or name no project. |
| `workspace_binding_conflict` | A request named the project in a form its connection cannot use: a server-elsewhere `client:` handle sent to this computer's FinishUP, or a folder path and a server-elsewhere claim together. | Name the project by its folder path through FinishUP's own tools; a hand-written client must not send a `client:` handle to a local server. |
| `task_input_outside_not_admitted` | A task names a file or folder outside your project that review may not read: no folder you listed for that server covers it, nor does the server's own privacy policy. The rest of the work was checked. | On this computer, in your own terminal: `finishup server folders add NAME FOLDER` with that file's folder, in either mode. Then check again. |
| `folder_invalid` | `server folders add` was given a folder it cannot admit: not a full path, missing, reached through a link, hidden, a system folder, or your home folder, a folder that holds it or one of its private folders. | Give the full path of the existing folder you mean, inside your home folder if it is there. |
| `folders_record_invalid`, `folders_record_unsafe` | The record of what a server may read outside your projects on this computer is damaged or not private to you, so that server reads no folder outside them, in listed mode, whatever mode you chose. `server status`, `server folders list` and `/server` say so too. | On this computer, run `finishup server folders remove NAME --all`; then add the folders again (`finishup server folders add NAME FOLDER`), or choose local mode again (`finishup server folders mode NAME local`). |
| `outside_read_mode_invalid` | `server folders mode` or `server add --outside-reads` was given something other than `local` or `listed`. | Give `local` or `listed`. |
| `outside_reads_not_chosen` | `server add` asked what the server may read outside your projects, and no answer chose: Enter alone or another word three times, end of input, or Ctrl-C. Nothing was added. | Run the command again and type `local` or `listed` when asked, or add `--outside-reads local` or `--outside-reads listed`. |

In the terminal interface, the header shows which server is in use, and `/server` lists your
servers and can switch between them with the same confirmation. Adding a server there asks where
it runs and, for a server on another machine, a port or the web, the same question as `server
add`; it then prints the `finishup server add` command with your answer for you to run in your
shell. As with `server add`, an official FinishUP service is not asked: where one exists,
`/server` offers it as its own choice and prints its command without an answer. Its status view shows the server's mode and the folders listed for it, and it prints the
`finishup server folders` commands for you to run in your shell.
