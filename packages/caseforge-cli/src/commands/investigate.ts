/**
 * `caseforge investigate <evidence-path>` — run a privacy-gated DFIR
 * investigation with the VERDICT agent + forensic MCP tools.
 *
 * The privacy router decides whether the chosen route may be used for the
 * evidence class BEFORE any model is contacted. In local-only mode a cloud
 * route is refused outright — no evidence leaves the host.
 */
import { spawn, spawnSync, execFileSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { assertModelAllowed, DEFAULT_PRIVACY_MODE, PrivacyViolationError, assembleVerdictFromAudit } from "@verdict/caseforge-sdk"
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { chatGptOAuthStatus, printChatGptOAuthSetup, verdictLauncherPath } from "../chatgpt-auth.js"
import {
  loadRoutes,
  loadRoutingPolicy,
  normalizeOpenAiCompatBaseUrl,
  resolveCandidate,
  opencodeProfileDir,
  routeLocation,
  routeRequiresChatGptOAuth,
} from "../config.js"
import { verify } from "./verify.js"

const CASE_OPEN_EXTENSIONS = [".evtx", ".pcap", ".pcapng", ".e01", ".dd", ".raw", ".aff", ".mem", ".ova", ".zip"]

export interface ResolvedEvidenceInput {
  requestedPath: string
  caseOpenPath: string
  inventory: string[]
  isDirectory: boolean
}

function supportedEvidenceNames(inventory: string[]): string[] {
  return inventory.filter((name) => CASE_OPEN_EXTENSIONS.some((ext) => name.toLowerCase().endsWith(ext)))
}

function caseOpenExtensionPriority(name: string): number {
  const lower = name.toLowerCase()
  const idx = CASE_OPEN_EXTENSIONS.findIndex((ext) => lower.endsWith(ext))
  return idx === -1 ? Number.POSITIVE_INFINITY : idx
}

export function resolveEvidenceInput(evidencePath: string): ResolvedEvidenceInput {
  const st = statSync(evidencePath)
  if (st.isFile()) {
    return { requestedPath: evidencePath, caseOpenPath: evidencePath, inventory: [evidencePath], isDirectory: false }
  }
  if (!st.isDirectory()) throw new Error(`evidence path is not a regular file or directory: ${evidencePath}`)

  const inventory = readdirSync(evidencePath, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort((a, b) => a.localeCompare(b))

  if (inventory.length === 0) {
    throw new Error(`evidence directory is empty: ${evidencePath}`)
  }

  const supported = supportedEvidenceNames(inventory)
  if (supported.length === 0) {
    throw new Error(
      `evidence directory has no supported case_open image (${CASE_OPEN_EXTENSIONS.join(", ")}): ${evidencePath}` +
        (inventory.length ? `; found: ${inventory.join(", ")}` : ""),
    )
  }

  // findevil-mcp_case_open requires a REGULAR FILE (not a directory). Prefer the
  // first supported inventory member by CASE_OPEN_EXTENSIONS priority so the
  // agent prompt never hands the directory path to case_open.
  const primaryName = [...supported].sort(
    (a, b) => caseOpenExtensionPriority(a) - caseOpenExtensionPriority(b) || a.localeCompare(b),
  )[0]
  if (!primaryName) {
    throw new Error(`evidence directory has no supported case_open image: ${evidencePath}`)
  }
  const primaryPath = join(evidencePath, primaryName)

  return {
    requestedPath: evidencePath,
    caseOpenPath: primaryPath,
    inventory,
    isDirectory: true,
  }
}

function evidenceToolHint(evidence: ResolvedEvidenceInput, findevilHome?: string): string {
  if (evidence.isDirectory) {
    const supported = supportedEvidenceNames(evidence.inventory).sort(
      (a, b) => caseOpenExtensionPriority(a) - caseOpenExtensionPriority(b) || a.localeCompare(b),
    )
    const fullPaths = supported.map((name) => join(evidence.requestedPath, name))
    const openAll =
      fullPaths.length > 1
        ? ` Then call findevil-mcp_case_open (or the matching per-artifact tool) on EVERY remaining inventory file in order: ${fullPaths
            .slice(1)
            .map((p) => `'${p}'`)
            .join(", ")}. Never pass the directory path '${evidence.requestedPath}' to case_open — it must be a regular file.`
        : ` Never pass the directory path '${evidence.requestedPath}' to case_open — it must be a regular file.`
    return (
      `Evidence type hint: directory of artifacts. Call findevil-mcp_case_open with image_path exactly '${evidence.caseOpenPath}' first` +
      (supported.length ? ` (inventory basenames: ${supported.join(", ")})` : "") +
      `.` +
      openAll +
      ` For each .evtx file, call findevil-mcp_evtx_query without an eids filter first (survey Event IDs), then focused re-queries. Do not collapse multi-file evidence to a single file when deciding the scoped verdict.\n`
    )
  }

  const lower = evidence.caseOpenPath.toLowerCase()
  if (lower.endsWith(".evtx")) {
    const custodyHint = findevilHome
      ? `After case_open returns case_id, set case_dir to '${findevilHome}/cases/' + case_id; audit_log_path to case_dir + '/audit.jsonl'; manifest_path to case_dir + '/run.manifest.json'. `
      : ""
    return (
      `Evidence type hint: single EVTX. Run this mandatory tool sequence without stopping for user input and without printing JSON examples: ` +
      `(A) findevil-mcp_case_open with image_path exactly '${evidence.caseOpenPath}'; ` +
      `(B) findevil-mcp_evtx_query with case_id from case_open and evtx_path exactly '${evidence.caseOpenPath}' — Do NOT pass an eids filter on the first query (limit 500 survey). From the tool RESULT, list which Event IDs are present (read event_id fields; do not invent). If Event ID 1102 (audit-log cleared) is present, that is anti-forensics evidence: verdict must be SUSPICIOUS or INDETERMINATE, never NO_EVIL. Optional second query may filter eids only after the survey shows them; ` +
      `(C) findevil-agent-mcp_audit_append kind 'tool_call_output' for the EVTX query. payload.tool_name='evtx_query'; payload.arguments=the query args; payload.output_summary MUST be a JSON OBJECT (not a prose string) with records_seen, row_count, and rows: array of {event_id, record_id, channel, ts} copied from the tool result (include every 1102 row at minimum). Do not invent output_hash/output_sha256; ` +
      `(D) findevil-agent-mcp_audit_verify with path=audit_log_path; ` +
      `(E) findevil-agent-mcp_manifest_finalize (omit signer or signer:'ed25519' — never signer:'stub') with case_id, audit_log_path, output_path=manifest_path; ` +
      `(F) findevil-agent-mcp_manifest_verify with manifest_path set to that run.manifest.json. ` +
      custodyHint +
      `CRITICAL: after (B) you MUST continue through (C)(D)(E)(F) in the same session — never stop after only case_open/evtx_query. After (F) returns overall:true, stop. Do not print tool calls as markdown/JSON code blocks — only real structured MCP tool calls. ` +
      `For a single EVTX you may seal audited tool outputs without finding_approved when verify_finding was not run. Do not call disk_mount or disk_extract_artifacts for a single EVTX file.\n`
    )
  }
  if (lower.endsWith(".pcap") || lower.endsWith(".pcapng")) {
    return `Evidence type hint: packet capture. After findevil-mcp_case_open, prefer findevil-mcp_pcap_triage / findevil-mcp_zeek_summary; do not use disk_mount.\n`
  }
  return ""
}

/**
 * Independently verify the sealed manifest and persist manifest_verify.json.
 *
 * The agent's manifest_verify runs AFTER manifest_finalize seals the audit chain,
 * so its result is not written anywhere. caseforge re-verifies the signed
 * run.manifest.json itself with the toolkit's zero-dependency offline verifier
 * (`scripts/manifest-verify-offline.py`) — the "LLM is not the source of truth"
 * step for custody — and writes the result to manifest_verify.json.
 */
function finalizeManifestVerify(runDir: string, dfirHome = process.env.VERDICT_DFIR_HOME): void {
  const manifest = join(runDir, "run.manifest.json")
  const out = join(runDir, "manifest_verify.json")
  if (!existsSync(manifest) || existsSync(out)) return
  const verifier = dfirHome ? join(dfirHome, "scripts", "manifest-verify-offline.py") : ""
  if (!verifier || !existsSync(verifier)) return
  try {
    const json = execFileSync("python3", [verifier, manifest, "--json"], { encoding: "utf8" })
    writeFileSync(out, json)
    console.error("[caseforge] independently re-verified the signed manifest -> manifest_verify.json")
  } catch (e) {
    // The verifier exits non-zero when the manifest does NOT verify, but still
    // prints its JSON verdict to stdout — capture it so custody-invalid is recorded.
    const stdout = (e as { stdout?: string }).stdout
    if (stdout) {
      writeFileSync(out, stdout)
      console.error("[caseforge] manifest FAILED independent verification -> manifest_verify.json")
    } else {
      console.error(`[caseforge] manifest verify step could not run: ${(e as Error).message}`)
    }
  }
}

/**
 * Assemble the structured verdict.json report from the sealed audit chain, so
 * the run comes out as a "full report" (findings + scoped verdict), not just
 * custody-sealed. caseforge-derived and clearly marked as such — the toolkit's
 * authoritative verdict.json comes only from its own auto-runner.
 */
/**
 * When the agent audited evtx_query with empty/fabricated rows, re-query 1102
 * via findevil-mcp and merge into the caseforge-derived verdict (not into audit).
 */
function enrichVerdictWithEvtx1102Probe(
  runDir: string,
  doc: { verdict?: string; findings?: unknown[]; evidence_path?: string; case_id?: string; [k: string]: unknown },
  dfirHome: string | undefined,
): typeof doc {
  if (!dfirHome) return doc
  const findings = Array.isArray(doc.findings) ? doc.findings : []
  if (findings.length > 0) return doc
  // dist/src/commands -> repo root scripts/ (5 levels up from this file in dist)
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    join(here, "../../../../../scripts/evtx-1102-probe.py"),
    join(process.cwd(), "scripts", "evtx-1102-probe.py"),
  ]
  const probePath = candidates.find((p) => existsSync(p))
  if (!probePath) return doc

  let evtxPath = typeof doc.evidence_path === "string" ? doc.evidence_path : ""
  let caseId = typeof doc.case_id === "string" ? doc.case_id : ""
  if (!evtxPath || !caseId) {
    try {
      const caseJson = JSON.parse(readFileSync(join(runDir, "case.json"), "utf8")) as {
        id?: string
        case_id?: string
        evidence_path?: string
        image_path?: string
      }
      caseId = caseId || caseJson.id || caseJson.case_id || ""
      evtxPath = evtxPath || caseJson.evidence_path || caseJson.image_path || ""
    } catch {
      /* ignore */
    }
  }
  // Fallback: audit arguments
  if (!evtxPath || !caseId) {
    try {
      const audit = readFileSync(join(runDir, "audit.jsonl"), "utf8")
      for (const line of audit.split("\n")) {
        if (!line.trim()) continue
        const row = JSON.parse(line) as { payload?: { arguments?: { case_id?: string; evtx_path?: string } } }
        const a = row.payload?.arguments
        if (a?.evtx_path) evtxPath = evtxPath || a.evtx_path
        if (a?.case_id) caseId = caseId || a.case_id
      }
    } catch {
      /* ignore */
    }
  }
  if (!evtxPath || !evtxPath.toLowerCase().endsWith(".evtx")) return doc

  const args = [probePath, "--evtx", evtxPath]
  if (caseId) args.push("--case-id", caseId)
  const result = spawnSync("python3", args, {
    encoding: "utf8",
    env: { ...process.env, VERDICT_DFIR_HOME: dfirHome },
    timeout: 120_000,
  })
  if (result.status !== 0 || !result.stdout?.trim()) {
    console.error(
      `[caseforge] evtx-1102-probe skipped/failed: ${(result.stderr || result.stdout || "").slice(0, 200)}`,
    )
    return doc
  }
  let parsed: { ok?: boolean; rows?: Array<Record<string, unknown>> }
  try {
    parsed = JSON.parse(result.stdout.trim().split("\n").pop() || "{}") as typeof parsed
  } catch {
    return doc
  }
  if (!parsed.ok || !Array.isArray(parsed.rows) || parsed.rows.length === 0) return doc

  // HYPOTHESIS: probe re-query is not an audit-chain leaf (no tool_call_id in the
  // sealed hash chain). Still surfaces EID 1102 for the caseforge-derived report
  // when the agent sealed with empty fabricated rows.
  const enrichedFindings = parsed.rows.map((r, i) => {
    const recordId = r.record_id
    const ts = typeof r.ts === "string" ? r.ts : undefined
    const channel = typeof r.channel === "string" ? r.channel : "Security"
    const when = ts ? ` at ${ts}` : ""
    const recordSuffix = typeof recordId === "string" || typeof recordId === "number" ? String(recordId) : String(i + 1)
    return {
      finding_id: `evtx-1102-probe-${recordSuffix}`,
      verdict: "SUSPICIOUS",
      confidence: "HYPOTHESIS",
      description: `hypothesis: ${channel} audit log cleared (Event ID 1102)${when}; record_id=${recordSuffix} (caseforge re-query after agent audit omitted structured rows).`,
      tool_name: "evtx_query",
      case_id: caseId || undefined,
      evidence_path: evtxPath,
      event_id: 1102,
      channel,
      record_id: recordId,
      ts,
    }
  })
  console.error(
    `[caseforge] enriched verdict with ${enrichedFindings.length} EVTX 1102 row(s) from findevil-mcp re-query (agent audit had empty rows)`,
  )
  return {
    ...doc,
    verdict: "SUSPICIOUS",
    findings: enrichedFindings,
    case_completeness: {
      ...(typeof doc.case_completeness === "object" && doc.case_completeness ? doc.case_completeness : {}),
      generated_by_caseforge: true,
      note: "Derived from audit.jsonl by caseforge; 1102 rows enriched via findevil-mcp re-query when agent audit omitted structured rows.",
    },
  }
}

async function finalizeVerdictJson(runDir: string, dfirHome = process.env.VERDICT_DFIR_HOME): Promise<void> {
  const out = join(runDir, "verdict.json")
  // Overwrite missing or caseforge-derived verdicts from audit (structured 1102 rows).
  // Preserve toolkit auto-runner / other authoritative verdict.json files.
  if (existsSync(out)) {
    try {
      const prev = JSON.parse(readFileSync(out, "utf8")) as { generated_by?: string }
      if (prev.generated_by !== "caseforge") return
    } catch {
      return
    }
  }
  let doc = await assembleVerdictFromAudit(runDir)
  if (!doc) return
  doc = enrichVerdictWithEvtx1102Probe(runDir, doc, dfirHome) as typeof doc
  writeFileSync(out, JSON.stringify(doc, null, 2) + "\n")
  console.error(
    `[caseforge] assembled verdict.json from the audit chain — verdict ${doc.verdict}, ${doc.findings.length} cited finding(s)`,
  )
}

/**
 * Path handed to find_evil_auto.py for the deterministic EVTX fallback.
 *
 * - Single .evtx file → that file.
 * - Directory containing one or more .evtx → the directory itself, so
 *   find_evil_auto inventory mode opens every EVTX (not just the first
 *   lexicographic name). That is what made win-lateral-movement miss the WMI
 *   file when the agent collapsed case_open and the fallback could not fire
 *   because caseOpenPath was a directory (no .evtx suffix).
 * - Non-EVTX / empty → undefined (no EVTX fallback).
 */
export function resolveEvtxFallbackPath(evidence: ResolvedEvidenceInput): string | undefined {
  if (!evidence.isDirectory) {
    return evidence.caseOpenPath.toLowerCase().endsWith(".evtx") ? evidence.caseOpenPath : undefined
  }
  const supported = supportedEvidenceNames(evidence.inventory)
  const evtxNames = supported.filter((name) => name.toLowerCase().endsWith(".evtx"))
  if (evtxNames.length === 0) return undefined
  // Directory path → inventory mode enumerates all EVTX under the case dir.
  return evidence.requestedPath
}

function runLocalEvtxAutoFallback(evidence: ResolvedEvidenceInput, env: NodeJS.ProcessEnv, mode: "primary" | "fallback" = "fallback"): string | undefined {
  const fallbackPath = resolveEvtxFallbackPath(evidence)
  if (!fallbackPath) return undefined
  const dfirHome = env.VERDICT_DFIR_HOME
  if (!dfirHome) return undefined
  const auto = join(dfirHome, "scripts", "find_evil_auto.py")
  if (!existsSync(auto)) return undefined

  const summaryDir = env.TMPDIR ?? process.cwd()
  mkdirSync(summaryDir, { recursive: true })
  const summaryPath = join(summaryDir, `caseforge-auto-fallback-${Date.now()}.json`)
  const multi = evidence.isDirectory
    ? ` (directory scope — find_evil_auto will open every EVTX under ${fallbackPath})`
    : ""
  if (mode === "primary") {
    console.error(
      `[caseforge] local EVTX primary path: deterministic find_evil_auto engine${multi} (custody-first; set CASEFORGE_FORCE_AGENT=1 to force opencode agent).`,
    )
  } else {
    console.error(
      `[caseforge] agent run did not produce a complete sealed EVTX run; using deterministic local EVTX auto-runner fallback${multi}.`,
    )
  }
  const result = spawnSync(
    "python3",
    [auto, "--local", "--unattended", "--no-report", "--signer", "ed25519", "--run-summary", summaryPath, fallbackPath],
    { cwd: dfirHome, env, stdio: "inherit" },
  )
  if (result.status !== 0) {
    console.error(`[caseforge] EVTX auto-runner fallback failed with exit ${result.status ?? "unknown"}`)
    return undefined
  }
  try {
    const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as { run_dir?: string; result?: { local_dir?: string; case_dir_in_vm?: string } }
    const runDir = summary.run_dir ?? summary.result?.local_dir ?? summary.result?.case_dir_in_vm
    if (runDir && existsSync(runDir)) return runDir
  } catch {
    /* fall through */
  }
  console.error("[caseforge] EVTX auto-runner fallback completed but no run directory was found in its summary.")
  return undefined
}

/** Newest VERDICT case dir under FINDEVIL_HOME/cases, if any. */
function findNewestCaseDir(dfirHome: string | undefined, findevilHome: string | undefined, newerThanMs = 0): string | undefined {
  const home = findevilHome ?? (dfirHome ? join(dfirHome, ".project-local", "findevil") : undefined)
  if (!home) return undefined
  const cases = join(home, "cases")
  if (!existsSync(cases)) return undefined
  let newest: { dir: string; mtime: number } | undefined
  for (const name of readdirSync(cases)) {
    const dir = join(cases, name)
    try {
      const st = statSync(dir)
      if (st.isDirectory() && st.mtimeMs > newerThanMs && (!newest || st.mtimeMs > newest.mtime)) newest = { dir, mtime: st.mtimeMs }
    } catch {
      /* skip */
    }
  }
  return newest?.dir
}

/**
 * Mirror VERDICT's scripts/lib/project-env.sh defaults for launched MCP tools.
 *
 * This keeps forensic runtime state under the Dev checkout's gitignored
 * .project-local tree. The parent caseforge process is left untouched.
 */
function withDfirContainment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const dfirHome = env.VERDICT_DFIR_HOME
  if (!dfirHome) return env

  const projectLocal = env.PROJECT_LOCAL ?? join(dfirHome, ".project-local")
  const toolchain = join(projectLocal, "toolchain")
  for (const dir of [
    join(projectLocal, "tmp"),
    join(projectLocal, "home"),
    join(projectLocal, "config"),
    join(projectLocal, "share"),
    join(projectLocal, "state"),
    join(projectLocal, "state", "findevil"),
    join(projectLocal, "cache"),
    join(projectLocal, "findevil"),
    join(projectLocal, "npm"),
    join(projectLocal, "ms-playwright"),
    join(projectLocal, "puppeteer"),
    join(toolchain, "cargo"),
    join(toolchain, "rustup"),
    join(toolchain, "uv-cache"),
    join(toolchain, "uv-python"),
    join(toolchain, "pnpm-store"),
  ]) {
    mkdirSync(dir, { recursive: true })
  }

  const xdgStateHome = env.XDG_STATE_HOME ?? join(projectLocal, "state")
  const cargoHome = env.CARGO_HOME ?? join(toolchain, "cargo")
  return {
    ...env,
    PROJECT_ROOT: env.PROJECT_ROOT ?? dfirHome,
    PROJECT_LOCAL: projectLocal,
    OPENCODE_TEST_HOME: env.OPENCODE_TEST_HOME ?? join(projectLocal, "home"),
    TMPDIR: env.TMPDIR ?? join(projectLocal, "tmp"),
    XDG_CONFIG_HOME: env.XDG_CONFIG_HOME ?? join(projectLocal, "config"),
    XDG_DATA_HOME: env.XDG_DATA_HOME ?? join(projectLocal, "share"),
    XDG_STATE_HOME: xdgStateHome,
    XDG_CACHE_HOME: env.XDG_CACHE_HOME ?? join(projectLocal, "cache"),
    FINDEVIL_HOME: env.FINDEVIL_HOME ?? join(projectLocal, "findevil"),
    FINDEVIL_MEMORY_STORE: env.FINDEVIL_MEMORY_STORE ?? join(xdgStateHome, "findevil", "memory.sqlite"),
    HAYABUSA_RULES_BASE: env.HAYABUSA_RULES_BASE ?? join(env.XDG_DATA_HOME ?? join(projectLocal, "share"), "hayabusa-mcp"),
    npm_config_cache: env.npm_config_cache ?? join(projectLocal, "npm"),
    PLAYWRIGHT_BROWSERS_PATH: env.PLAYWRIGHT_BROWSERS_PATH ?? join(projectLocal, "ms-playwright"),
    PUPPETEER_CACHE_DIR: env.PUPPETEER_CACHE_DIR ?? join(projectLocal, "puppeteer"),
    CARGO_HOME: cargoHome,
    RUSTUP_HOME: env.RUSTUP_HOME ?? join(toolchain, "rustup"),
    UV_CACHE_DIR: env.UV_CACHE_DIR ?? join(toolchain, "uv-cache"),
    UV_PYTHON_INSTALL_DIR: env.UV_PYTHON_INSTALL_DIR ?? join(toolchain, "uv-python"),
    PNPM_HOME: env.PNPM_HOME ?? join(toolchain, "pnpm-store"),
    OPENCODE_DISABLE_EXTERNAL_SKILLS: env.OPENCODE_DISABLE_EXTERNAL_SKILLS ?? "1",
    OPENCODE_DISABLE_CLAUDE_CODE_SKILLS: env.OPENCODE_DISABLE_CLAUDE_CODE_SKILLS ?? "1",
    PATH: `${join(homedir(), ".cargo", "bin")}:${join(cargoHome, "bin")}:${env.PATH ?? ""}`,
  }
}

export interface InvestigateOpts {
  privacy?: PrivacyMode
  evidence?: EvidenceClass
  route?: string
  command?: string // opencode slash command to drive (default: triage)
  runDir?: string // explicit run/case dir to verify afterwards
  noVerify?: boolean
}

function isRouteAllowed(id: string, opts: { privacy: PrivacyMode; evidenceClass: EvidenceClass }): boolean {
  const resolved = resolveCandidate(id)
  if (!resolved) return false
  try {
    assertModelAllowed(resolved.candidate, { mode: opts.privacy, evidenceClass: opts.evidenceClass })
    return true
  } catch {
    return false
  }
}

function policyDefaultRoute(opts: { evidenceClass: EvidenceClass }): string | undefined {
  const policy = loadRoutingPolicy()
  return opts.evidenceClass === "sensitive" ? policy.sensitive_default : policy.non_sensitive_default
}

/** Pick the requested route, then the configured policy default, then any allowed fallback. */
export function chooseRoute(opts: { privacy: PrivacyMode; evidenceClass: EvidenceClass; route?: string }): string | undefined {
  if (opts.route) return opts.route
  const preferred = policyDefaultRoute(opts)
  if (preferred && isRouteAllowed(preferred, opts)) return preferred
  for (const id of Object.keys(loadRoutes())) {
    if (id === preferred) continue
    if (isRouteAllowed(id, opts)) return id
  }
  return undefined
}

export async function investigate(evidencePath: string | undefined, opts: InvestigateOpts): Promise<number> {
  if (!evidencePath) {
    console.error("usage: caseforge investigate <evidence-path> [--privacy MODE] [--evidence CLASS] [--route ID]")
    return 2
  }
  if (!existsSync(evidencePath)) {
    console.error(`evidence path not found: ${evidencePath}`)
    return 2
  }
  const canonicalEvidencePath = realpathSync(evidencePath)
  let evidence: ResolvedEvidenceInput
  try {
    evidence = resolveEvidenceInput(canonicalEvidencePath)
  } catch (e) {
    console.error((e as Error).message)
    return 2
  }
  const mode = opts.privacy ?? (process.env.CASEFORGE_PRIVACY as PrivacyMode) ?? DEFAULT_PRIVACY_MODE
  const evidenceClass = opts.evidence ?? "sensitive"

  const routeId = chooseRoute({ privacy: mode, evidenceClass, route: opts.route })
  if (!routeId) {
    console.error(`no route permitted under privacy='${mode}', evidence='${evidenceClass}'.`)
    console.error("Add a local route, reclassify/approve/redact the evidence, or change --privacy.")
    return 1
  }
  const resolved = resolveCandidate(routeId)
  if (!resolved) {
    console.error(`route '${routeId}' not found in configs/model-routes.yaml`)
    return 2
  }

  // Hard privacy gate — throws PrivacyViolationError if disallowed.
  try {
    assertModelAllowed(resolved.candidate, { mode, evidenceClass })
  } catch (e) {
    if (e instanceof PrivacyViolationError) {
      console.error(`REFUSED: ${e.message}`)
      return 1
    }
    throw e
  }

  const { route } = resolved
  let oauthAuthPath: string | undefined
  if (routeRequiresChatGptOAuth(route)) {
    if (route.provider !== "openai") {
      console.error(`route '${routeId}' is marked auth=chatgpt-oauth but provider is '${route.provider}', expected 'openai'.`)
      return 2
    }
    const status = chatGptOAuthStatus()
    if (!status.ok) {
      console.error(`route '${routeId}' requires ChatGPT subscription OAuth, but it is not ready: ${status.reason}`)
      console.error("OpenAI Platform API keys are not accepted for this route.")
      printChatGptOAuthSetup()
      return 1
    }
    if (status.source === "file") oauthAuthPath = status.authPath
  }

  // Map a route to an opencode model ref + env.
  const env: NodeJS.ProcessEnv = withDfirContainment({
    ...process.env,
    OPENCODE_CONFIG: join(opencodeProfileDir(), "opencode.json"),
    OPENCODE_CONFIG_DIR: opencodeProfileDir(),
  })
  let modelRef: string
  if (routeLocation(route) === "local") {
    modelRef = "verdict-local/local"
    // A remote self-hosted endpoint (e.g. Ollama on a DGX Spark over the LAN) is
    // still "local" for privacy — evidence stays on your own hardware. Let an
    // explicit VERDICT_LLM_BASEURL / VERDICT_LLM_MODEL env override the route so
    // one route can target localhost or a Spark by just exporting the endpoint.
    // openai-compatible client POSTs ${baseURL}/chat/completions — bare Ollama
    // roots (no /v1) 404; normalize so VERDICT_LLM_BASEURL=http://host:11434 works.
    env.VERDICT_LLM_BASEURL = normalizeOpenAiCompatBaseUrl(
      process.env.VERDICT_LLM_BASEURL ?? route.base_url ?? "http://localhost:11434/v1",
    )
    env.VERDICT_LLM_APIKEY = process.env.VERDICT_LLM_APIKEY ?? "local"
    env.VERDICT_LLM_MODEL = process.env.VERDICT_LLM_MODEL ?? route.model
    // Force structured tool calls on non-final steps for weak local models
    // (llama3.1 often prints JSON prose instead of MCP tool invocations).
    // Opt out with OPENCODE_TOOL_CHOICE=auto or VERDICT_FORCE_TOOL_CHOICE=0.
    if (process.env.VERDICT_FORCE_TOOL_CHOICE !== "0") {
      env.OPENCODE_TOOL_CHOICE = process.env.OPENCODE_TOOL_CHOICE ?? "required"
      env.VERDICT_FORCE_TOOL_CHOICE = process.env.VERDICT_FORCE_TOOL_CHOICE ?? "1"
    }
  } else {
    // cloud provider handled by opencode's built-in catalog + auth
    modelRef = `${route.provider}/${route.model}`
    if (routeRequiresChatGptOAuth(route)) {
      delete env.OPENAI_API_KEY
      if (!env.OPENCODE_AUTH_CONTENT && oauthAuthPath) env.OPENCODE_AUTH_CONTENT = readFileSync(oauthAuthPath, "utf8")
    }
  }

  const command = opts.command ?? "triage"
  const memoryStorePath = env.FINDEVIL_MEMORY_STORE ?? (env.XDG_STATE_HOME ? join(env.XDG_STATE_HOME, "findevil", "memory.sqlite") : undefined)
  const inventoryText =
    evidence.isDirectory && evidence.inventory.length
      ? `Evidence directory inventory (exact filenames only, do not guess alternatives): ${evidence.inventory.join(", ")}.\n`
      : ""
  const toolHint = evidenceToolHint(evidence, env.FINDEVIL_HOME)
  // Drive the COMPLETE flow: the evidence-type playbook, then the /verdict
  // reason+seal phase. The run only counts as complete when the manifest is
  // finalized AND manifest_verify reports overall:true — otherwise the produced
  // case is a partial (unsealed) run and `caseforge verify` will reject it.
  const prompt =
    `This is an authorized, defensive DFIR lab investigation against local evidence controlled by the operator. ` +
    `Do not exploit, evade, persist, or access any live third-party system; only use the read-only forensic MCP tools to inspect the supplied local evidence.\n` +
    `Complete a VERDICT investigation of the evidence input: ${evidence.requestedPath}.\n` +
    `Case-open evidence path: ${evidence.caseOpenPath}.\n` +
    inventoryText +
    toolHint +
    `1. Perform the ${command} workflow directly with MCP tool calls: open the case, call the appropriate forensic MCP tools, and audit each important tool output with findevil-agent-mcp_audit_append.\n` +
    `2. Then perform the reason+seal phase directly with MCP tool calls. If you have verified cited findings, use verify_finding, judge_findings, and correlate_findings. If you do not have verified cited findings, skip finding_approved and seal the audited tool outputs only. Always run findevil-agent-mcp_audit_verify, then SEAL with findevil-agent-mcp_manifest_finalize (write run.manifest.json into the case directory), then call findevil-agent-mcp_manifest_verify. Do NOT pass signer:'stub' to manifest_finalize — omit signer (the default is the real offline-verifiable ed25519 local signature) or pass signer:'ed25519'; a stub placeholder never satisfies custody. Call findevil-agent-mcp_manifest_verify with the argument named manifest_path set to the run.manifest.json path.\n` +
    (memoryStorePath ? `3. Use MEMORY_STORE_PATH exactly as '${memoryStorePath}' for every memory_recall or memory_remember call; never use ~/.local/state/findevil/memory.sqlite in this run.\n` : "") +
    `SEALING RULE (critical): Multi-class evidence is required for CONFIRMED findings only — NOT for sealing. ` +
    `Single-class EVTX directories (one or more .evtx files only) MUST still complete audit_verify → manifest_finalize → manifest_verify. ` +
    `Verdict may be INDETERMINATE with HYPOTHESIS findings. Never stop because you lack three artifact classes.\n` +
    `Preferred local-EVTX tool allowlist (use these exact names only when possible): ` +
    `findevil-mcp_case_open, findevil-mcp_evtx_query, findevil-agent-mcp_audit_append, findevil-agent-mcp_audit_verify, ` +
    `findevil-agent-mcp_manifest_finalize, findevil-agent-mcp_manifest_verify, findevil-agent-mcp_verify_finding, findevil-agent-mcp_judge_findings. ` +
    `Never invent a tool named invalid, run, bash, or shell.\n` +
    `Use only the VERDICT forensic MCP tools with their exact opencode names: findevil-mcp_<tool> and findevil-agent-mcp_<tool>. ` +
    `Open the supplied evidence first with findevil-mcp_case_open using ONLY these args: image_path exactly '${evidence.caseOpenPath}' ` +
    `(required regular file, never a directory); optional expected_sha256, label. Do NOT pass case_dir, case_id, or other fields to case_open. ` +
    `Never call or invent findevil-agent-mcp_case_open, and never guess alternate image names such as evidence.dd or evidence.e01. ` +
    `If case_open fails, fix the path and retry — do not stop with prose-only analysis. ` +
    `Every tool call name must start with findevil-mcp_ or findevil-agent-mcp_. There is no tool named run; do not call a run tool, task tool, skill tool, todowrite tool, or slash command. ` +
    `Use findevil-mcp_* for evidence/artifact tools and findevil-agent-mcp_* only for reasoning, judging, correlation, memory, and manifest sealing. Manifest tools are ONLY findevil-agent-mcp_manifest_finalize and findevil-agent-mcp_manifest_verify; never call findevil-mcp_manifest_finalize or findevil-mcp_manifest_verify. ` +
    `Call MCP tools directly with structured arguments; do not type MCP tool names into shell/bash and do not print JSON examples instead of making real tool calls. ` +
    `Never print a fenced code block or prose "function call" JSON as a substitute for an MCP tool invocation — if you need a tool, invoke it; if you are done sealing, stop. ` +
    `Never claim that a tool call, audit append, manifest finalize, or manifest verify happened unless the corresponding MCP tool actually returned; in particular, do not say manifest verification completed unless findevil-agent-mcp_manifest_verify returned overall:true. ` +
    `Do not invent underscore variants such as findevil_mcp_manifest_finalize. Do not use shell/bash/read/write/edit/list/grep/glob to inspect evidence or create ad hoc rules. Operate read-only on evidence. ` +
    `Negative-control discipline: suspicious filenames, planted strings, topic notes, archives named passwords, and sinkhole/parked-domain lookups are non-reportable decoy leads unless independent execution, persistence, credential access, C2, or data-movement evidence exists. ` +
    `Scope the verdict to SUSPICIOUS / INDETERMINATE / NO_EVIL. ` +
    `The investigation is NOT complete unless manifest_verify reports overall:true and a real run.manifest.json plus audit.jsonl exist in the produced case directory — do not stop before the manifest is finalized and verified. After those files exist and overall:true, end the turn.`
  // Local EVTX: custody-first engine as primary (gpt-oss/opencode often fabricates MCP).
  // Set CASEFORGE_FORCE_AGENT=1 to force the opencode agent path instead.
  const forceAgent = process.env.CASEFORGE_FORCE_AGENT === "1"
  if (!forceAgent && routeLocation(route) === "local" && resolveEvtxFallbackPath(evidence)) {
    console.error(`[caseforge] route=${routeId} model=${modelRef} privacy=${mode} evidence=${evidenceClass}`)
    console.error(`[caseforge] evidence=${evidence.requestedPath}`)
    if (evidence.caseOpenPath !== evidence.requestedPath) console.error(`[caseforge] case_open=${evidence.caseOpenPath}`)
    const engineDir = runLocalEvtxAutoFallback(evidence, env, "primary")
    if (engineDir) {
      console.error(`\n[caseforge] verifying primary engine run: ${engineDir}`)
      return await verify([engineDir])
    }
    console.error("[caseforge] primary engine path failed; falling through to opencode agent")
  }

  console.error(`[caseforge] route=${routeId} model=${modelRef} privacy=${mode} evidence=${evidenceClass}`)
  console.error(`[caseforge] evidence=${evidence.requestedPath}`)
  if (evidence.caseOpenPath !== evidence.requestedPath) console.error(`[caseforge] case_open=${evidence.caseOpenPath}`)

  const bin = verdictLauncherPath(env)
  const launchedAtMs = Date.now() - 1000

  const runAgent = (message: string): Promise<number> =>
    new Promise<number>((resolvePromise) => {
      const child = spawn(bin, ["run", "--pure", "--agent", "verdict", "--model", modelRef, message], {
        env,
        stdio: "inherit",
      })
      child.on("error", (err) => {
        console.error(`failed to launch ${bin}: ${err.message}`)
        resolvePromise(1)
      })
      child.on("exit", (code) => resolvePromise(code ?? 0))
    })

  const caseIsSealed = (dir: string | undefined): boolean =>
    !!dir && existsSync(join(dir, "run.manifest.json")) && existsSync(join(dir, "audit.jsonl"))

  let runCode = await runAgent(prompt)
  let runDir = opts.runDir ?? findNewestCaseDir(env.VERDICT_DFIR_HOME, env.FINDEVIL_HOME, launchedAtMs)

  // One seal-continue attempt: local models often stop after case_open/evtx_query.
  // Re-enter with a short prompt that forbids re-open and requires C→F only.
  if (!opts.noVerify && !caseIsSealed(runDir) && resolveEvtxFallbackPath(evidence)) {
    const caseId = runDir && existsSync(join(runDir, "case.json"))
      ? (() => {
          try {
            const raw = JSON.parse(readFileSync(join(runDir!, "case.json"), "utf8")) as { id?: string; case_id?: string }
            return raw.id ?? raw.case_id
          } catch {
            return undefined
          }
        })()
      : undefined
    const continuePrompt =
      `CONTINUE the authorized DFIR lab investigation of ${evidence.caseOpenPath}. ` +
      (caseId
        ? `case_id is already ${caseId}; case_dir is under the findevil cases directory for that id. Do NOT call case_open again. `
        : `If you already have a case_id from a prior case_open, reuse it; only call case_open if you truly have none. `) +
      `Immediately complete only: (B) findevil-mcp_evtx_query with the exact evtx_path (survey limit 500, no eids filter first) if not already done; ` +
      `(C) findevil-agent-mcp_audit_append with payload.output_summary as a JSON OBJECT including rows:[{event_id,record_id,channel,ts}] copied from the tool result (every Event ID 1102 row required when present — never a prose-only summary string); ` +
      `(D) findevil-agent-mcp_audit_verify; (E) findevil-agent-mcp_manifest_finalize (signer omit or ed25519); (F) findevil-agent-mcp_manifest_verify. ` +
      `If Event ID 1102 is in the tool result, do not claim NO_EVIL. Stop only when manifest_verify returns overall:true. Real MCP tool calls only — no printed JSON.`
    console.error("[caseforge] agent case incomplete (missing seal artifacts); one seal-continue attempt…")
    const contCode = await runAgent(continuePrompt)
    runCode = contCode === 0 ? 0 : runCode
    runDir = opts.runDir ?? findNewestCaseDir(env.VERDICT_DFIR_HOME, env.FINDEVIL_HOME, launchedAtMs) ?? runDir
  }

  if (opts.noVerify) return runCode

  // Close the loop: locate the produced run/case dir and validate it.
  // CASEFORGE_NO_AGENT_FALLBACK=1: fail closed (no find_evil_auto) for strict agent measurement.
  const noAgentFallback = process.env.CASEFORGE_NO_AGENT_FALLBACK === "1"
  if (!runDir) {
    console.error("[caseforge] investigation finished; no fresh run/case dir was produced to verify.")
    console.error("[caseforge] the run is incomplete until a new case directory is sealed and verified.")
    if (noAgentFallback) {
      console.error("[caseforge] CASEFORGE_NO_AGENT_FALLBACK=1 — skipping deterministic EVTX fallback")
      return runCode === 0 ? 1 : runCode
    }
    const fallbackRunDir = runLocalEvtxAutoFallback(evidence, env)
    if (fallbackRunDir) {
      console.error(`\n[caseforge] verifying deterministic EVTX fallback run: ${fallbackRunDir}`)
      return await verify([fallbackRunDir])
    }
    return runCode === 0 ? 1 : runCode
  }
  // Independently confirm custody (writes manifest_verify.json), assemble the
  // structured verdict.json report from the audit chain, then validate.
  finalizeManifestVerify(runDir, env.VERDICT_DFIR_HOME)
  await finalizeVerdictJson(runDir, env.VERDICT_DFIR_HOME)
  console.error(`\n[caseforge] verifying produced run: ${runDir}`)
  let verifyCode = await verify([runDir])
  let fallbackVerified = false
  if (verifyCode !== 0 || !caseIsSealed(runDir)) {
    if (noAgentFallback) {
      console.error("[caseforge] CASEFORGE_NO_AGENT_FALLBACK=1 — agent seal incomplete; not using find_evil_auto")
      return verifyCode !== 0 ? verifyCode : 1
    }
    const fallbackRunDir = runLocalEvtxAutoFallback(evidence, env)
    if (fallbackRunDir) {
      console.error(`\n[caseforge] verifying deterministic EVTX fallback run: ${fallbackRunDir}`)
      verifyCode = await verify([fallbackRunDir])
      fallbackVerified = verifyCode === 0
    }
  }
  // Non-zero if the agent run failed OR the produced run does not verify.
  return fallbackVerified ? 0 : runCode !== 0 ? runCode : verifyCode
}
