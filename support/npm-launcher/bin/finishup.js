#!/usr/bin/env node
"use strict";

// Delegation-only launcher: `npx finishup ...` installs the exact pinned Python
// distribution as a persistent uv tool and runs it through uv. It never bundles
// Python, never downloads code itself, and never rewrites arguments — the Python
// CLI owns every behavior, including the first-run experience on a bare
// interactive invocation.
//
// Because stdio is inherited, the child sees the *real* terminal: the same
// stdin/stdout TTY checks that gate the full-screen interface, and the same
// controlling terminal the confidential credential ceremony requires. Anything
// that captured or replaced these streams here would silently downgrade both.

const { spawnSync } = require("node:child_process");
const { constants } = require("node:os");
const { version } = require("../package.json");

const INSTALL_DOCS = "https://docs.astral.sh/uv/getting-started/installation/";

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
    // The packaging contract forbids bootstrapping a runtime from here, so the
    // only useful thing this launcher can do is say exactly what is missing and
    // exactly how to get it.
    fail([
      "finishup: the 'uv' tool is required and was not found on PATH.",
      "",
      "FinishUP runs on Python 3.14 and this launcher only delegates to the",
      `Python distribution 'finishup==${version}'. It never installs anything itself,`,
      "so uv has to be present first.",
      "",
      "  macOS / Linux:  curl -LsSf https://astral.sh/uv/install.sh | sh",
      "  Windows:        powershell -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
      `  Other options:  ${INSTALL_DOCS}`,
      "",
      "Then re-run this command.",
    ]);
    return;
  }
  if (uvProbe.error || uvProbe.status !== 0) {
    const reported = uvProbe.error
      ? uvProbe.error.message
      : `'uv --version' exited with status ${uvProbe.status}`;
    fail([
      "finishup: could not run 'uv --version'.",
      "",
      `Reported: ${reported}`,
      "",
      "Check that your uv installation is executable and complete,",
      `then re-run this command. See ${INSTALL_DOCS}`,
    ]);
    return;
  }

  // Make the exact version a persistent uv tool first (a no-op when it already
  // is). Hooks and MCP entries bind the absolute path of the launcher that
  // configured them; a bare `uvx` would bind them to uv's prunable cache and a
  // later `uv cache clean` would silently break every host integration. uv
  // still performs the provenance-carrying install from PyPI; this launcher
  // bundles and downloads nothing. `--python 3.14` lets uv fetch the runtime
  // when no suitable interpreter is present, whatever other Pythons exist.
  const install = spawnSync(
    "uv",
    ["tool", "install", "--quiet", "--python", "3.14", `finishup==${version}`],
    { stdio: "inherit", shell: false },
  );
  if (install.error || install.status !== 0) {
    const reported = install.error
      ? install.error.message
      : `'uv tool install' exited with status ${install.status}`;
    fail([
      `finishup: could not install the Python distribution 'finishup==${version}' with uv.`,
      "",
      `Reported: ${reported}`,
      "",
      "FinishUP needs Python 3.14. uv downloads it on demand unless Python downloads are",
      "disabled in your uv configuration; the message above names the exact cause.",
      `See ${INSTALL_DOCS}`,
    ]);
    return;
  }

  // A versionless `uvx finishup` runs the installed tool environment, never a
  // cache-backed one, so the child is the same persistent launcher that
  // `~/.local/bin/finishup` points at. The exact version was pinned by the install
  // above; repeating it here could only ever select a different environment.
  const result = spawnSync(
    "uvx",
    ["--python", "3.14", "finishup", ...process.argv.slice(2)],
    { stdio: "inherit", shell: false },
  );

  if (result.error) {
    fail([
      "finishup: found 'uv' but could not launch 'uvx'.",
      "",
      `Reported: ${result.error.message}`,
      "",
      "Check that your uv installation is complete and that 'uvx' is on PATH,",
      `then re-run this command. See ${INSTALL_DOCS}`,
    ]);
    return;
  }

  // A child killed by a signal has no exit status. Reporting the conventional
  // 128+n keeps `npx finishup` interchangeable with the Python entry point in a
  // script that inspects exit codes — including 130 for an interrupted session.
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
