#!/usr/bin/env node
/**
 * caseforge self-test — asserts the model-independent MVP guarantees:
 *  - privacy router respects mode (local-only blocks cloud; cloud-ok gates on class)
 *  - invalid findings are rejected (no evidence / bad hash)
 *  - route config keeps ChatGPT OAuth distinct from OpenAI API keys
 *  - missing VERDICT artifacts => run incomplete
 *  - failed manifest verification => custody-invalid
 *  - citation custody: unknown tool_call_id / mismatched hash => not verified
 */
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"
import {
  decideModel,
  validateFinding,
  validateRun,
  loadAudit,
  verifyCitations,
  REQUIRED_ARTIFACTS,
} from "../packages/caseforge-sdk/dist/src/index.js"

let pass = 0,
  fail = 0
const ok = (name, cond) => (cond ? (pass++, console.log(`  PASS ${name}`)) : (fail++, console.log(`  FAIL ${name}`)))

const local = { id: "local-ollama", location: "local" }
const cloud = { id: "openai", location: "cloud" }

console.log("privacy router:")
ok("local-only blocks cloud", decideModel(cloud, { mode: "local-only" }).allowed === false)
ok("local-only allows local", decideModel(local, { mode: "local-only" }).allowed === true)
ok("cloud-ok allows synthetic cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "synthetic" }).allowed === true)
ok("cloud-ok blocks sensitive cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "sensitive" }).allowed === false)
ok("redacted-cloud needs redaction", decideModel(cloud, { mode: "redacted-cloud" }).allowed === false)
ok("redacted-cloud allows when redacted", decideModel(cloud, { mode: "redacted-cloud", redacted: true }).allowed === true)
ok("default fail-closed (unknown class, cloud-ok) blocks", decideModel(cloud, { mode: "cloud-ok" }).allowed === false)

console.log("route config:")
{
  const { loadRoutes, loadRoutingPolicy, routeLocation, routeRequiresChatGptOAuth } = await import("../packages/caseforge-cli/dist/src/config.js")
  const { chooseRoute, resolveEvidenceInput } = await import("../packages/caseforge-cli/dist/src/commands/investigate.js")
  const { verdictLauncherPath } = await import("../packages/caseforge-cli/dist/src/chatgpt-auth.js")
  const routes = loadRoutes()
  const policy = loadRoutingPolicy()
  ok("chatgpt-oauth route exists", Boolean(routes["chatgpt-oauth"]))
  ok("chatgpt-oauth is cloud + oauth guarded", routeLocation(routes["chatgpt-oauth"]) === "cloud" && routeRequiresChatGptOAuth(routes["chatgpt-oauth"]))
  ok("non-sensitive default prefers ChatGPT OAuth", policy.non_sensitive_default === "chatgpt-oauth")
  ok("non-sensitive route selection uses policy default", chooseRoute({ privacy: "cloud-ok", evidenceClass: "synthetic" }) === "chatgpt-oauth")
  ok("sensitive route selection uses policy local default", chooseRoute({ privacy: "local-only", evidenceClass: "sensitive" }) === policy.sensitive_default)
  ok("OpenAI API route is explicitly named", Boolean(routes["openai-api"]) && routes["openai-api"].auth === "api-key")
  ok("ChatGPT auth uses repo-local verdict launcher", verdictLauncherPath({}) === fileURLToPath(new URL("../bin/verdict", import.meta.url)))
  const launcher = readFileSync(fileURLToPath(new URL("../bin/verdict", import.meta.url)), "utf8")
  ok("verdict launcher delegates to external runtime", !/caseforge\/engine|DEFAULT_BIN|VERDICT_WS|build-engine/.test(launcher))
  ok("verdict launcher falls back to installed opencode", /type -P -a opencode/.test(launcher) && /\.opencode\/bin\/opencode/.test(launcher))
  ok("verdict launcher refuses recursive launch", /VERDICT_BIN points back to this CaseForge launcher/.test(launcher) && /\$resolved" != "\$SELF/.test(launcher))
  const investigateSrc = readFileSync(fileURLToPath(new URL("../packages/caseforge-cli/src/commands/investigate.ts", import.meta.url)), "utf8")
  ok("investigate launches isolated opencode profile", /"run",\s*"--pure",\s*"--agent",\s*"verdict"/.test(investigateSrc))
  ok("investigate prompt scopes authorized defensive DFIR", /authorized, defensive DFIR lab investigation/.test(investigateSrc) && /read-only forensic MCP tools/.test(investigateSrc))
  ok("investigate contains opencode global state", /OPENCODE_TEST_HOME/.test(investigateSrc) && /XDG_CONFIG_HOME/.test(investigateSrc) && /OPENCODE_DISABLE_EXTERNAL_SKILLS/.test(investigateSrc))
  ok("investigate prompt routes case_open to Rust MCP", /findevil-mcp_case_open/.test(investigateSrc) && /never call or invent findevil-agent-mcp_case_open/.test(investigateSrc))
  ok("investigate prompt routes single EVTX to evtx_query", /single EVTX/.test(investigateSrc) && /findevil-mcp_evtx_query/.test(investigateSrc) && /Do not call disk_mount/.test(investigateSrc))
  ok("investigate prompt avoids helper tool confusion", /Every tool call name must start with findevil-mcp_/.test(investigateSrc) && /do not call a run tool, task tool, skill tool, todowrite tool/.test(investigateSrc))
  ok("investigate pins manifest tools to agent MCP", /Manifest tools are ONLY findevil-agent-mcp_manifest_finalize/.test(investigateSrc) && /never call findevil-mcp_manifest_finalize/.test(investigateSrc))
  ok("investigate requires verified manifest before complete", /manifest_verify reports overall:true/.test(investigateSrc) && /real run\.manifest\.json plus audit\.jsonl/.test(investigateSrc))
  const evidenceDir = mkdtempSync(join(tmpdir(), "caseforge-evidence-"))
  try {
    writeFileSync(join(evidenceDir, "manifest.json"), "{}")
    writeFileSync(join(evidenceDir, "image.E01"), "tiny")
    const resolved = resolveEvidenceInput(evidenceDir)
    ok("directory evidence stays directory-scoped for case_open", resolved.caseOpenPath === evidenceDir && resolved.inventory.includes("image.E01"))
  } finally {
    rmSync(evidenceDir, { recursive: true, force: true })
  }
  const evtxDir = mkdtempSync(join(tmpdir(), "caseforge-evtx-"))
  try {
    const evtxFile = join(evtxDir, "DE_1102_security_log_cleared.evtx")
    writeFileSync(evtxFile, "tiny")
    const resolved = resolveEvidenceInput(evtxFile)
    ok("single EVTX evidence opens exact file", resolved.isDirectory === false && resolved.caseOpenPath === evtxFile)
  } finally {
    rmSync(evtxDir, { recursive: true, force: true })
  }
}

console.log("opencode profile guardrails:")
{
  const profile = JSON.parse(readFileSync(fileURLToPath(new URL("../configs/opencode/opencode.json", import.meta.url)), "utf8"))
  ok(
    "opencode profile denies by default but allows VERDICT MCP tools",
    profile.permission?.["*"] === "deny" &&
      profile.permission?.["findevil-mcp_*"] === "allow" &&
      profile.permission?.["findevil-agent-mcp_*"] === "allow",
  )
  ok("opencode profile denies helper prompts", profile.permission?.question === "deny" && profile.permission?.plan_enter === "deny" && profile.permission?.plan_exit === "deny")
  const agentNames = ["verdict", "pool-a", "pool-b", "verifier", "judge", "correlator"]
  for (const name of agentNames) {
    const text = readFileSync(fileURLToPath(new URL(`../configs/opencode/agent/${name}.md`, import.meta.url)), "utf8")
    ok(`${name}: shell/direct FS tools denied`, /bash:\s+deny/.test(text) && /read:\s+deny/.test(text) && /grep:\s+deny/.test(text) && /glob:\s+deny/.test(text) && /list:\s+deny/.test(text))
    ok(`${name}: opencode helper tools denied`, /task:\s+deny/.test(text) && /skill:\s+deny/.test(text) && /todowrite:\s+deny/.test(text))
    ok(
      `${name}: exact MCP tool families allowed`,
      /["']?findevil-mcp_\*["']?:\s+allow/.test(text) && /["']?findevil-agent-mcp_\*["']?:\s+allow/.test(text) && !/^\s*mcp_\*:\s+allow/m.test(text),
    )
  }
  const skill = readFileSync(fileURLToPath(new URL("../configs/opencode/skill/verdict-dfir/SKILL.md", import.meta.url)), "utf8")
  ok("skill names exact opencode MCP tools", /findevil-mcp_case_open/.test(skill) && /findevil-agent-mcp_manifest_verify/.test(skill) && /do not invent underscore variants/i.test(skill))
  const triage = readFileSync(fileURLToPath(new URL("../configs/opencode/command/triage.md", import.meta.url)), "utf8")
  const verdict = readFileSync(fileURLToPath(new URL("../configs/opencode/command/verdict.md", import.meta.url)), "utf8")
  ok("triage command uses exact MCP names", /findevil-mcp_case_open/.test(triage) && /findevil-mcp_disk_mount/.test(triage) && /findevil-agent-mcp_detect_contradictions/.test(triage))
  ok("verdict command uses exact MCP names", /findevil-agent-mcp_audit_verify/.test(verdict) && /findevil-agent-mcp_manifest_finalize/.test(verdict) && /findevil-agent-mcp_manifest_verify/.test(verdict) && /findevil_mcp_manifest_finalize/.test(verdict))
  ok("verdict command forbids Rust manifest variants", /Never call\s+`findevil-mcp_manifest_finalize`/.test(verdict) && /`findevil-mcp_manifest_verify`/.test(verdict))
  ok("verdict command does not require nonexistent report_qa", !/report_qa/.test(verdict))
  ok("triage command has negative-control gate", /Negative-control gate/.test(triage) && /name\/content bait/.test(triage))
  ok("verdict command rejects decoy-only findings", /Do not accept Findings/.test(verdict) && /negative-control leads/.test(verdict))
  ok("verdict skill forbids Rust manifest tools", /Never call\s+`findevil-mcp_manifest_finalize`/.test(skill) && /findevil_mcp_manifest_finalize/.test(skill))
  const verdictAgent = readFileSync(fileURLToPath(new URL("../configs/opencode/agent/verdict.md", import.meta.url)), "utf8")
  ok("verdict agent treats workflows as labels not slash commands", /Evidence-type workflow labels/.test(verdictAgent) && /not slash commands/.test(verdictAgent) && /Do not call a `run`/.test(verdictAgent))
  ok("verdict agent local profile avoids task helper", /local locked profile does not expose subagent helper tools/.test(verdictAgent) && /Do not call `task`/.test(verdictAgent))
}

console.log("finding validator:")
const sha = "a".repeat(64)
ok("rejects finding with no evidence", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [] }).valid === false)
ok("rejects bad sha", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: "nothex" }] }).valid === false)
ok("rejects bad verdict word", validateFinding({ id: "1", title: "t", verdict: "GUILTY", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === false)
ok("accepts valid finding", validateFinding({ id: "1", title: "t", verdict: "NO_EVIL", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === true)

console.log("artifact + custody validator:")
const dir = mkdtempSync(join(tmpdir(), "caseforge-run-"))
try {
  // 1. empty dir => incomplete (missing the hard custody files)
  let r = await validateRun(dir)
  ok("missing custody => incomplete", r.status === "incomplete" && r.missing.includes("run.manifest.json") && r.missing.includes("audit.jsonl"))

  // 2. all present but manifest verify fails => custody-invalid
  for (const a of REQUIRED_ARTIFACTS) writeFileSync(join(dir, a), a.endsWith(".jsonl") ? "" : "{}")
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: false }))
  r = await validateRun(dir)
  ok("failed manifest verify => custody-invalid", r.status === "custody-invalid")

  // 3. auto-runner shape: all present and verified => complete (full report)
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: true }))
  writeFileSync(join(dir, "verdict.json"), JSON.stringify({ attack_coverage: {}, findings: [] }))
  r = await validateRun(dir)
  ok("auto-runner: all present + verified => complete", r.status === "complete" && r.custodyValid === true)

  // 4. interactive agent seal: only run.manifest.json + audit.jsonl (seal on the
  //    audit chain, no manifest_verify.json / verdict.json) => complete (custody-sealed)
  const seal = mkdtempSync(join(tmpdir(), "caseforge-seal-"))
  try {
    writeFileSync(join(seal, "run.manifest.json"), "{}")
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: true } } }) + "\n",
    )
    const rs = await validateRun(seal)
    ok("interactive seal (audit-chain) => complete", rs.status === "complete" && rs.custodyValid === true)
    // negative: same but overall:false => custody-invalid
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: false } } }) + "\n",
    )
    const rf = await validateRun(seal)
    ok("interactive seal overall:false => custody-invalid", rf.status === "custody-invalid")
  } finally {
    rmSync(seal, { recursive: true, force: true })
  }

  // 4. citation custody against audit.jsonl
  writeFileSync(
    join(dir, "audit.jsonl"),
    JSON.stringify({ tool_call_id: "c1", output_sha256: sha }) + "\n",
  )
  const audit = await loadAudit(dir)
  ok("citation matches audit => verified", verifyCitations([{ tool_call_id: "c1", output_sha256: sha }], audit).verified === true)
  ok("unknown tool_call_id => not verified", verifyCitations([{ tool_call_id: "nope", output_sha256: sha }], audit).verified === false)
  ok("hash mismatch => not verified", verifyCitations([{ tool_call_id: "c1", output_sha256: "b".repeat(64) }], audit).verified === false)
} finally {
  rmSync(dir, { recursive: true, force: true })
}

console.log("tui workbench:")
{
  const { loadCase } = await import("../packages/caseforge-tui/dist/src/load.js")
  const { renderHeader, renderFindings, renderScreen } = await import("../packages/caseforge-tui/dist/src/render.js")
  const fixDir = fileURLToPath(new URL("../fixtures/synthetic/sample-run", import.meta.url))
  const v = await loadCase(fixDir)
  ok("tui: fixture run validates complete + custody re-verified", v.validation.status === "complete" && v.validation.custodyValid === true)
  ok("tui: header renders verdict + dual custody lights", /SUSPICIOUS/.test(renderHeader(v)) && /re-verified now/.test(renderHeader(v)))
  ok("tui: findings render cited tool_call_id", /tc-1/.test(renderFindings(v)) && /cited/.test(renderFindings(v)))
  ok("tui: screen composes all panels", renderScreen(v).length > 200)
  const vb = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/broken-chain-run", import.meta.url)))
  ok("tui: broken audit chain caught (chainOk false)", vb.chainOk === false)
  const vn = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/no-report-run", import.meta.url)))
  ok("tui: missing verdict.json degrades but custody holds", vn.verdict === undefined && vn.validation.custodyValid === true)
  const { listRuns } = await import("../packages/caseforge-tui/dist/src/picker.js")
  const { renderPicker } = await import("../packages/caseforge-tui/dist/src/render.js")
  const runs = await listRuns([fileURLToPath(new URL("../fixtures/synthetic", import.meta.url))])
  ok("tui: picker discovers runs with validated status", runs.length >= 3 && /CASES/.test(renderPicker(runs)))
  const { keyOf, reduce, initialState } = await import("../packages/caseforge-tui/dist/src/app.js")
  ok("tui: keyOf maps arrow/enter/quit", keyOf("\x1b[A") === "up" && keyOf("\r") === "enter" && keyOf("\x03") === "quit")
  ok("tui: reduce navigates picker<->case", reduce(reduce(initialState, "enter", 3), "back", 3).view === "picker")
  ok("tui: picker flags a structurally-broken audit chain", runs.some((r) => /broken-chain-run/.test(r.dir) && r.chainOk === false) && /⚠ chain/.test(renderPicker(runs)))
  const { renderHeader: rh } = await import("../packages/caseforge-tui/dist/src/render.js")
  const ci = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/custody-invalid-run", import.meta.url)))
  ok("tui: custody-invalid run re-verifies as invalid", ci.validation.status === "custody-invalid" && ci.validation.custodyValid === false)
  const { renderCustodyBanner } = await import("../packages/caseforge-tui/dist/src/render.js")
  ok("tui: invalid custody warns over findings; valid does not", /CUSTODY NOT VERIFIED/.test(renderCustodyBanner(ci)) && renderCustodyBanner(v) === "")
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
