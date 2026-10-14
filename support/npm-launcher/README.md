# finishup npm launcher

This package is a **delegation launcher only**. `npx finishup` installs the exact
pinned Python distribution `finishup==<this package's version>` as a persistent tool through
[`uv`](https://docs.astral.sh/uv/), which must already be installed, and runs it. The launcher:

- bundles no Python, no dependencies, and no FinishUP code;
- downloads nothing itself — `uv tool install --python 3.14` performs the provenance-carrying
  install from PyPI (fetching the Python 3.14 runtime on demand), and a versionless `uvx finishup`
  then runs that installed environment rather than a cache-backed one. `uv tool install` places
  `finishup` in uv's tool bin (`~/.local/bin`); if that directory is not on `PATH`, run
  `uv tool update-shell` and open another terminal. Agents connected from `npx finishup` survive
  `uv cache clean`;
- passes every argument through unchanged and exits with the child's exit code, reporting the
  conventional `128+n` when the child is killed by a signal so `npx finishup` and the Python
  console script are interchangeable in a script that inspects exit codes;
- inherits stdio, so the child process sees the *real* terminal. This is load-bearing twice
  over: the same stdin/stdout TTY checks gate the full-screen interface (ADR-017), and the
  confidential credential ceremony requires the controlling terminal. Capturing or replacing
  these streams here would silently downgrade both.
- keeps its version in lockstep with the PyPI `finishup` version, so the two distribution
  surfaces can never silently drift.

A bare interactive `npx finishup` therefore reaches the same full-screen first run the Python CLI
owns; this package adds no behavior of its own and duplicates no setup or interface logic.

## Coming from `npx yoetz`

FinishUP was called Yoetz through 0.2.5. `npx finishup` installs a separate `finishup` tool; it
never replaces, renames or removes an existing `yoetz` tool and never passes `--force` to uv. Agents
connected through the earlier tool keep running it until you reconnect them to `finishup`; only
then remove the old tool with `uv tool uninstall yoetz`. The deprecated `yoetz` npm package keeps
`npx yoetz` working for one release by updating that existing tool in place.

## When `uv` is missing

The packaging contract forbids bootstrapping a runtime from here, so the launcher does not try.
It prints what is missing, the platform-appropriate install command, and the fact that it
installs nothing itself — then exits 1 without running anything.

## Publication and provenance

The standing maintainer decision publishes this launcher as the public `finishup` npm package, one
release per tagged FinishUP version. The tagged release workflow builds its tarball once, records its
SHA-256, publishes the exact tarball through npm trusted publishing only after the Python
distribution of the same version is live on PyPI, and downloads it back for byte comparison. npm's package provenance binds the public tarball to that
GitHub Actions workflow.

The launcher remains only a delegator. npm installation does not install Python, `uv`, FinishUP's
Python code, or any runtime dependency; it selects the same exact-version PyPI distribution that
the release workflow already published and verified.
