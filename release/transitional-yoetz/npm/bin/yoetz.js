#!/usr/bin/env node
"use strict";

// Deprecated transitional launcher (ADR-048): Yoetz is now FinishUP. `npx yoetz ...` keeps
// the earlier launcher's exact behavior for one release: it installs the exact pinned Python
// distribution `yoetz==<version>` as a persistent uv tool and runs it through uv. That Python
// distribution is itself transitional: it installs the same-version `finishup` and keeps the
// `yoetz` command as an alias, so host hooks and MCP entries bound to the earlier `yoetz` tool
// keep running from the same place after the update. New installations use `npx finishup`.
//
// It never bundles Python, never downloads code itself, never rewrites arguments, and never
// passes `--force` to uv: replacing or removing another installation is the user's decision,
// and a refused install is reported with uv's own message.
//
// Because stdio is inherited, the child sees the *real* terminal: the same stdin/stdout TTY
// checks that gate the full-screen interface, and the same controlling terminal the
// confidential credential ceremony requires.

const { spawnSync } = require("node:child_process");
const { constants } = require("node:os");
const { version } = require("../package.json");

const INSTALL_DOCS = "https://docs.astral.sh/uv/getting-started/installation/";
const MIGRATION_DOCS =
  "https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md#upgrading-from-yoetz";

function probeUv() {
  return spawnSync("uv", ["--version"], { stdio: "ignore", shell: false });
}

function fail(lines) {
  process.stderr.write(lines.concat("").join("\n"));
  process.exitCode = 1;
}

function main() {
  const uvProbe = probeUv();
  if (uvProbe.error?.code === "ENOENT") {
    fail([
      "yoetz: the 'uv' tool is required and was not found on PATH.",
      "",
      "Yoetz is now FinishUP. It runs on Python 3.14 and this launcher only delegates to the",
      `Python distribution 'yoetz==${version}'. It never installs anything itself,`,
      "so uv has to be present first.",
      "",
      "  macOS / Linux:  curl -LsSf https://astral.sh/uv/install.sh | sh",
      "  Windows:        powershell -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
      `  Other options:  ${INSTALL_DOCS}`,
      "",
      "Then re-run this command, or use 'npx finishup' for a new installation.",
    ]);
    return;
  }
  if (uvProbe.error || uvProbe.status !== 0) {
    const reported = uvProbe.error
      ? uvProbe.error.message
      : `'uv --version' exited with status ${uvProbe.status}`;
    fail([
      "yoetz: could not run 'uv --version'.",
      "",
      `Reported: ${reported}`,
      "",
      "Check that your uv installation is executable and complete,",
      `then re-run this command. See ${INSTALL_DOCS}`,
    ]);
    return;
  }

  // Make the exact version a persistent uv tool first (a no-op when it already is). This updates
  // an existing `yoetz` tool in place, which is what keeps earlier host registrations working.
  // No `--force`: if uv refuses, the user decides what to replace.
  const install = spawnSync(
    "uv",
    ["tool", "install", "--quiet", "--python", "3.14", `yoetz==${version}`],
    { stdio: "inherit", shell: false },
  );
  if (install.error || install.status !== 0) {
    const reported = install.error
      ? install.error.message
      : `'uv tool install' exited with status ${install.status}`;
    fail([
      `yoetz: could not install the Python distribution 'yoetz==${version}' with uv.`,
      "",
      `Reported: ${reported}`,
      "",
      "Nothing was replaced or removed. FinishUP needs Python 3.14; uv downloads it on demand",
      "unless Python downloads are disabled in your uv configuration. The message above names",
      `the exact cause. See ${INSTALL_DOCS}`,
      `To move to the new name instead, see ${MIGRATION_DOCS}`,
    ]);
    return;
  }

  // A versionless `uvx yoetz` runs the installed tool environment, never a cache-backed one.
  const result = spawnSync(
    "uvx",
    ["--python", "3.14", "yoetz", ...process.argv.slice(2)],
    { stdio: "inherit", shell: false },
  );

  if (result.error) {
    fail([
      "yoetz: found 'uv' but could not launch 'uvx'.",
      "",
      `Reported: ${result.error.message}`,
      "",
      "Check that your uv installation is complete and that 'uvx' is on PATH,",
      `then re-run this command. See ${INSTALL_DOCS}`,
    ]);
    return;
  }

  // A child killed by a signal has no exit status; report the conventional 128+n.
  if (result.status === null) {
    const SIGNAL_EXIT_BASE = 128;
    const offset =
      typeof result.signal === "number"
        ? result.signal
        : constants.signals[result.signal];
    process.exitCode = offset === undefined ? 1 : SIGNAL_EXIT_BASE + offset;
    return;
  }

  process.exitCode = result.status;
}

main();
