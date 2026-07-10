#!/usr/bin/env bash
# grok-cloud-smoke.sh — time-bounded caseforge investigate via xAI Grok cloud.
#
# Prerequisites (default route xai-grok-oauth):
#   caseforge auth login --provider xai --method headless|browser
#   OR for API key routes: XAI_API_KEY set + CASEFORGE_GROK_ROUTE=xai-grok
#   VERDICT_DFIR_HOME, VERDICT_BIN (or caseforge bin on PATH)
#   Network access to api.x.ai
#
# Privacy: uses cloud-ok + synthetic/public evidence only.
# Does NOT use Spark / local Ollama.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ROUTE="${CASEFORGE_GROK_ROUTE:-xai-grok-oauth}"
# Prefer SuperGrok OAuth; allow API key only for xai-grok / xai-grok-mini.
if [ "$ROUTE" = "xai-grok-oauth" ]; then
  if ! node packages/caseforge-cli/dist/src/cli.js auth status --provider xai >/dev/null 2>&1; then
    echo "SKIP: SuperGrok OAuth not configured — run: caseforge auth login --provider xai --method headless"
    exit 0
  fi
elif [ -z "${XAI_API_KEY:-}" ]; then
  echo "SKIP: XAI_API_KEY unset (and route is not xai-grok-oauth)"
  exit 0
fi

# Prefer env; else umbrella dev/ next to verdict-worktrees/
if [ -z "${VERDICT_DFIR_HOME:-}" ]; then
  if [ -d "$ROOT/../../verdict/dev" ]; then
    export VERDICT_DFIR_HOME="$(cd "$ROOT/../../verdict/dev" && pwd)"
  elif [ -d "$ROOT/../verdict/dev" ]; then
    export VERDICT_DFIR_HOME="$(cd "$ROOT/../verdict/dev" && pwd)"
  else
    export VERDICT_DFIR_HOME="${HOME}/Desktop/PUG-Projects/verdict/dev"
  fi
fi
if [ ! -d "${VERDICT_DFIR_HOME}" ]; then
  echo "FAIL: VERDICT_DFIR_HOME not a directory: ${VERDICT_DFIR_HOME}"
  exit 1
fi

BIN="${CASEFORGE_BIN:-}"
if [ -z "$BIN" ]; then
  if [ -x "$ROOT/bin/caseforge" ]; then BIN="$ROOT/bin/caseforge"
  elif command -v caseforge >/dev/null 2>&1; then BIN="$(command -v caseforge)"
  elif [ -f "$ROOT/packages/caseforge-cli/dist/src/cli.js" ]; then
    BIN="node $ROOT/packages/caseforge-cli/dist/src/cli.js"
  else
    echo "FAIL: caseforge CLI not found; build or set CASEFORGE_BIN"
    exit 1
  fi
fi

EVIDENCE="${CASEFORGE_GROK_EVIDENCE:-fixtures/synthetic}"
if [ ! -e "$EVIDENCE" ] && [ -e "${VERDICT_DFIR_HOME}/evidence/DE_1102_security_log_cleared.evtx" ]; then
  EVIDENCE="${VERDICT_DFIR_HOME}/evidence/DE_1102_security_log_cleared.evtx"
  EVIDENCE_CLASS="${CASEFORGE_GROK_EVIDENCE_CLASS:-public}"
else
  EVIDENCE_CLASS="${CASEFORGE_GROK_EVIDENCE_CLASS:-synthetic}"
fi

echo "==> Grok cloud smoke"
echo "    route=$ROUTE evidence=$EVIDENCE class=$EVIDENCE_CLASS privacy=cloud-ok"
echo "    VERDICT_DFIR_HOME=$VERDICT_DFIR_HOME"
if [ "$ROUTE" = "xai-grok-oauth" ]; then
  echo "    auth=SuperGrok OAuth (XAI_API_KEY cleared for child)"
else
  echo "    XAI_API_KEY is set (len=${#XAI_API_KEY})"
fi

# shellcheck disable=SC2086
$BIN models --privacy cloud-ok --evidence "$EVIDENCE_CLASS" || true

set +e
# shellcheck disable=SC2086
$BIN investigate "$EVIDENCE" \
  --privacy cloud-ok \
  --evidence "$EVIDENCE_CLASS" \
  --route "$ROUTE"
rc=$?
set -e

echo "==> investigate exit=$rc"
if [ "$rc" -eq 0 ]; then
  echo "PASS: grok-cloud investigate completed (rc=0)"
else
  echo "FAIL: grok-cloud investigate rc=$rc"
fi
exit "$rc"
