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
import { join } from "node:path"
import { assertModelAllowed, DEFAULT_PRIVACY_MODE, PrivacyViolationError, assembleVerdictFromAudit } from "@verdict/caseforge-sdk"
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { chatGptOAuthStatus, printChatGptOAuthSetup, verdictLauncherPath } from "../chatgpt-auth.js"
import { loadRoutes, loadRoutingPolicy, resolveCandidate, opencodeProfileDir, routeLocation, routeRequiresChatGptOAuth } from "../config.js"
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

  if (supportedEvidenceNames(inventory).length === 0) {
    throw new Error(
      `evidence directory has no supported case_open image (${CASE_OPEN_EXTENSIONS.join(", ")}): ${evidencePath}` +
        (inventory.length ? `; found: ${inventory.join(", ")}` : ""),
    )
  }

  return {
    requestedPath: evidencePath,
    caseOpenPath: evidencePath,
    inventory,
    isDirectory: true,
  }
}

function evidenceToolHint(evidence: ResolvedEvidenceInput, findevilHome?: string): string {
  if (evidence.isDirectory) {
    const supported = supportedEvidenceNames(evidence.inventory).sort((a, b) => caseOpenExtensionPriority(a) - caseOpenExtensionPriority(b) || a.localeCompare(b))
    return (
      `Evidence type hint: directory input. Call findevil-mcp_case_open with image_path exactly '${evidence.caseOpenPath}', then classify every supported artifact in the inventory` +
      (supported.length ? ` (${supported.join(", ")})` : "") +
      ` before deciding the scoped verdict. Do not collapse the directory to only one file.\n`
    )
  }

  const lower = evidence.caseOpenPath.toLowerCase()
  if (lower.endsWith(".evtx")) {
    const custodyHint = findevilHome
      ? `After case_open returns case_id, set case_dir to '${findevilHome}/cases/' + case_id; audit_log_path to case_dir + '/audit.jsonl'; manifest_path to case_dir + '/run.manifest.json'. `
      : ""
    return (
      `Evidence type hint: single EVTX. After findevil-mcp_case_open, call findevil-mcp_evtx_query with case_id from case_open and ` +
      `evtx_path exactly '${evidence.caseOpenPath}'. Do NOT pass an eids filter on the first query — survey which Event IDs are actually present (use a limit such as 500), then re-query focused on the DFIR-relevant ones you observed (for example 4624/4688 logon and process creation, 7045 service install, 1102 audit-log-cleared). Never assume a specific Event ID is present; a filter that matches nothing is not evidence of absence. ` +
      custodyHint +
      `Append the EVTX query result to audit_log_path with findevil-agent-mcp_audit_append kind 'tool_call_output' before sealing; use payload tool_name 'evtx_query', arguments, output or output_summary, and tool_call_id if the runtime exposes one. ` +
      `Do not invent output_hash or output_sha256 values. ` +
      `Do not emit finding_approved unless verify_finding approved a cited finding. Do not call disk_mount or disk_extract_artifacts for a single EVTX file.\n`
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
async function finalizeVerdictJson(runDir: string): Promise<void> {
  const out = join(runDir, "verdict.json")
  if (existsSync(out)) return
  const doc = await assembleVerdictFromAudit(runDir)
  if (!doc) return
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

function runLocalEvtxAutoFallback(evidence: ResolvedEvidenceInput, env: NodeJS.ProcessEnv): string | undefined {
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
  console.error(
    `[caseforge] agent run did not produce a complete sealed EVTX run; using deterministic local EVTX auto-runner fallback${multi}.`,
  )
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
    env.VERDICT_LLM_BASEURL = process.env.VERDICT_LLM_BASEURL ?? route.base_url ?? "http://localhost:11434/v1"
    env.VERDICT_LLM_APIKEY = process.env.VERDICT_LLM_APIKEY ?? "local"
    env.VERDICT_LLM_MODEL = process.env.VERDICT_LLM_MODEL ?? route.model
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
    `Use only the VERDICT forensic MCP tools with their exact opencode names: findevil-mcp_<tool> and findevil-agent-mcp_<tool>. ` +
    `Open the supplied evidence first with findevil-mcp_case_open using image_path exactly '${evidence.caseOpenPath}'; never call or invent findevil-agent-mcp_case_open, and never guess alternate image names such as evidence.dd or evidence.e01. ` +
    `Every tool call name must start with findevil-mcp_ or findevil-agent-mcp_. There is no tool named run; do not call a run tool, task tool, skill tool, todowrite tool, or slash command. ` +
    `Use findevil-mcp_* for evidence/artifact tools and findevil-agent-mcp_* only for reasoning, judging, correlation, memory, and manifest sealing. Manifest tools are ONLY findevil-agent-mcp_manifest_finalize and findevil-agent-mcp_manifest_verify; never call findevil-mcp_manifest_finalize or findevil-mcp_manifest_verify. ` +
    `Call MCP tools directly with structured arguments; do not type MCP tool names into shell/bash and do not print JSON examples instead of making real tool calls. ` +
    `Never claim that a tool call, audit append, manifest finalize, or manifest verify happened unless the corresponding MCP tool actually returned; in particular, do not say manifest verification completed unless findevil-agent-mcp_manifest_verify returned overall:true. ` +
    `Do not invent underscore variants such as findevil_mcp_manifest_finalize. Do not use shell/bash/read/write/edit/list/grep/glob to inspect evidence or create ad hoc rules. Operate read-only on evidence. ` +
    `Negative-control discipline: suspicious filenames, planted strings, topic notes, archives named passwords, and sinkhole/parked-domain lookups are non-reportable decoy leads unless independent execution, persistence, credential access, C2, or data-movement evidence exists. ` +
    `Scope the verdict to SUSPICIOUS / INDETERMINATE / NO_EVIL. ` +
    `The investigation is NOT complete unless manifest_verify reports overall:true and a real run.manifest.json plus audit.jsonl exist in the produced case directory — do not stop before the manifest is finalized and verified.`

  console.error(`[caseforge] route=${routeId} model=${modelRef} privacy=${mode} evidence=${evidenceClass}`)
  console.error(`[caseforge] evidence=${evidence.requestedPath}`)
  if (evidence.caseOpenPath !== evidence.requestedPath) console.error(`[caseforge] case_open=${evidence.caseOpenPath}`)

  const bin = verdictLauncherPath(env)
  const launchedAtMs = Date.now() - 1000
  const runCode = await new Promise<number>((resolvePromise) => {
    const child = spawn(bin, ["run", "--pure", "--agent", "verdict", "--model", modelRef, prompt], {
      env,
      stdio: "inherit",
    })
    child.on("error", (err) => {
      console.error(`failed to launch ${bin}: ${err.message}`)
      resolvePromise(1)
    })
    child.on("exit", (code) => resolvePromise(code ?? 0))
  })

  if (opts.noVerify) return runCode

  // Close the loop: locate the produced run/case dir and validate it.
  const runDir = opts.runDir ?? findNewestCaseDir(env.VERDICT_DFIR_HOME, env.FINDEVIL_HOME, launchedAtMs)
  if (!runDir) {
    console.error("[caseforge] investigation finished; no fresh run/case dir was produced to verify.")
    console.error("[caseforge] the run is incomplete until a new case directory is sealed and verified.")
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
  await finalizeVerdictJson(runDir)
  console.error(`\n[caseforge] verifying produced run: ${runDir}`)
  let verifyCode = await verify([runDir])
  let fallbackVerified = false
  if (verifyCode !== 0) {
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
