# Transitional `yoetz` distributions (ADR-048)

FinishUP shipped as Yoetz through 0.2.5. These two packages keep installations from that era
working for one deprecation release. They are built and published by `.github/workflows/release.yml`
next to `finishup`, at the same version, and carry no FinishUP code:

- `python/` — the PyPI `yoetz` distribution. It depends on `finishup==<same version>`, declares only
  the `yoetz` console script (`finishup.cli.entry:main`), and ships a top-level `yoetz` import shim
  so `python -m yoetz` and an older process's release-runtime bootstrap keep resolving.
- `npm/` — the npm `yoetz` launcher. It installs and runs the PyPI `yoetz` distribution of the same
  version, exactly as the earlier launcher did, and never passes `--force` to uv.

Version, dependency pin and extras stay in lockstep with the repository root, and the check also
asserts that `PACKAGE_EXTRAS` in `src/finishup/adapters/package_upgrade.py` (the extras `yoetz
upgrade` carries over to `finishup`) matches the root extras (`upgrade_extras_drift`,
`upgrade_extras_unreadable`):

```text
uv run python scripts/check_transitional_yoetz.py
uv build --no-sources release/transitional-yoetz/python --out-dir <dir>
uv run python scripts/check_transitional_yoetz.py --dist <dir>
```

Dropping the alias removes this directory, its release jobs, and the alias recognition in
`finishup.cli.entry`; do that only after status no longer reports host registrations bound to the
legacy launcher.
