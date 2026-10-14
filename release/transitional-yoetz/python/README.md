# yoetz (renamed to FinishUP)

Yoetz is now **FinishUP**. This package is a deprecated, transitional name kept for one release so
existing installations keep working while you move to the new name:

- it installs the same-version [`finishup`](https://pypi.org/project/finishup/) package, which
  contains all of the code;
- it keeps the `yoetz` command working as an alias of `finishup`, so agents connected by an earlier
  Yoetz release keep running. Any `finishup` command FinishUP shows also works as `yoetz` with the
  same subcommand. In an interactive terminal the alias prints a one-line notice;
- `yoetz upgrade` from an earlier release upgrades to this package in place.

FinishUP reads the existing Yoetz state, settings and agent registrations where they are; nothing
is moved or rewritten.

## Move to FinishUP

1. Install the new name: `uv tool install --managed-python --python 3.14.6 finishup`. If you
   installed `yoetz` with extras, install the same ones, for example
   `'finishup[semantic-openai]'`. `yoetz upgrade` prints this command with your extras when
   it can read them from the installation, and otherwise says to add them yourself.
2. Reconnect your agents to the `finishup` command. `finishup upgrade` shows the host refresh
   steps for each agent.
3. Only then remove the old name: `uv tool uninstall yoetz`. Agents connected earlier run the
   `yoetz` command until they are reconnected.

See [Upgrading from Yoetz](https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md#upgrading-from-yoetz).
