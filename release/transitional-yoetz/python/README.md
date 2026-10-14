# yoetz (renamed to FinishUP)

Yoetz is now **FinishUP**. This package is a deprecated, transitional name kept for one release so
existing installations keep working while you move to the new name:

- it installs the same-version [`finishup`](https://pypi.org/project/finishup/) package, which
  contains all of the code;
- it keeps the `yoetz` command working as an alias of `finishup`, so agents connected by an earlier
  Yoetz release keep running. Any `finishup` command FinishUP shows also works as `yoetz` with the
  same subcommand. In an interactive terminal the alias prints a one-line notice;
- an eligible unpinned 0.2.x `yoetz` tool reaches this package through its upgrade command;
  an exact-pinned tool needs the explicit requirement replacement below.

FinishUP reads the existing Yoetz state, settings and agent registrations where they are; nothing
is moved or rewritten.

## Update an older pinned installation

The released 0.2.1-0.2.5 upgrade command runs `uv tool upgrade yoetz`, which keeps an exact
`yoetz==0.2.5` pin, including one installed by the npm launcher. First follow the old release's
stop-first procedure for hosts, hooks and the service, then run
`uv tool install --upgrade 'yoetz>=0.3.0'`, carrying over the original extras, Python request and
package options. Check `yoetz --version` directly: the old command can report success while
leaving its pinned version installed. Version 0.1.0 has no `upgrade` command; use its package
manager. See the upgrade guide below for the complete procedure.

## Move to FinishUP

1. Install the new name: `uv tool install --compile-bytecode --managed-python --python 3.14.6 finishup`. If you
   installed `yoetz` with extras, install the same ones, for example
   `'finishup[semantic-openai]'`. `yoetz upgrade` prints this command with your extras when
   it can read them from the installation, and otherwise says to add them yourself.
2. Reconnect your agents to the `finishup` command. `finishup upgrade` shows the host refresh
   steps for each agent.
3. Only then remove the old name: `uv tool uninstall yoetz`. Agents connected earlier run the
   `yoetz` command until they are reconnected.

See [Upgrading from Yoetz](https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md#upgrading-from-yoetz).
