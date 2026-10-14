# yoetz npm launcher (renamed to finishup)

Yoetz is now **FinishUP**. Use [`npx finishup`](https://www.npmjs.com/package/finishup) for new
installations. This deprecated package is kept for one release so `npx yoetz` keeps working for
existing installations.

It is a **delegation launcher only**, exactly like the earlier `yoetz` launcher: `npx yoetz`
installs the exact pinned Python distribution `yoetz==<this package's version>` as a persistent
tool through [`uv`](https://docs.astral.sh/uv/), which must already be installed, and runs it.
That Python package is itself transitional: it installs the same-version `finishup` package and
keeps the `yoetz` command as an alias, so agents connected through the earlier `yoetz` tool keep
running from the same place after the update. Any `finishup` command FinishUP shows also works as
`npx yoetz` with the same subcommand. The launcher:

- bundles no Python, no dependencies, and no FinishUP code, and downloads nothing itself;
- never replaces or removes another installation: it never passes `--force` to uv. If uv refuses
  the install, the launcher reports uv's message and exits without running anything;
- passes every argument through unchanged, inherits stdio, and exits with the child's exit code
  (`128+n` for a child killed by a signal).

## Update a 0.2.x installation

First follow the old release's stop-first procedure for hosts, hooks and the service. Then run
the transitional version explicitly, for example `npx yoetz@0.3.0 --version`: an old installed or
cached 0.2.x npm launcher still requests its own old Python package version. The released Python
`yoetz upgrade` command also retains the exact pin made by npm, so its successful exit can leave
0.2.5 installed. Verify the fresh version directly before restarting the hosts.

To preserve extras or custom installation options, use
`uv tool install --upgrade 'yoetz>=0.3.0'` with those original extras, Python request and options
instead of the npm launcher. See the upgrade guide below.

## Move to FinishUP

1. Install the new name: `uv tool install --managed-python --python 3.14.6 finishup` (or run
   `npx finishup`). If you installed `yoetz` with extras, install the same ones, for example
   `'finishup[semantic-openai]'`. `yoetz upgrade` prints this command with your extras when
   it can read them from the installation, and otherwise says to add them yourself.
2. Reconnect your agents to the `finishup` command. `finishup upgrade` shows the host refresh
   steps for each agent.
3. Only then remove the old name: `uv tool uninstall yoetz`.

See [Upgrading from Yoetz](https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md#upgrading-from-yoetz).
