# Synthetic fixtures

Synthetic, shareable run artifacts used by CI and smoke tests. NEVER place real
or seized evidence here; CI treats this tree as public. Point
`caseforge investigate` at a real case directory locally (under local-only mode)
instead.

- `minimal-complete-run/`: smallest complete read-only run for the CaseForge TUI
  header smoke test. It carries a verdict word, recorded `manifest_verify`
  status, and enough custody artifacts for live SDK `validateRun` re-checks.
