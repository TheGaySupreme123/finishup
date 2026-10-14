"""Unattended dogfood lane for GitHub-hosted runners (contributor tooling, not shipped).

`lane.py` provisions a disposable FinishUP instance from the checkout, walks the product's own
setup path (service, vault, provider, privacy, host connection, observation), runs a bounded
ledger probe and one tiny native agent session, drains observation, restarts and unlocks the
service, and disposes the instance. `ceremony.py` drives the trusted-console ceremonies from a
real pseudo-terminal so a CI runner can supply run-scoped secrets. Documented in
``docs/runbooks/dogfood-ci.md``.
"""
