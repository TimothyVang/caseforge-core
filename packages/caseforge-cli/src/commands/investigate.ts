/**
 * `caseforge investigate <evidence-path>` — run a privacy-gated DFIR
 * investigation with the VERDICT agent + forensic MCP tools.
 *
 * The privacy router decides whether the chosen route may be used for the
 * evidence class BEFORE any model is contacted. In local-only mode a cloud
 * route is refused outright — no evidence leaves the host.
 */
import { spawn, execFileSync } from "node:child_process"
import { existsSync, readdirSync, statSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { assertModelAllowed, DEFAULT_PRIVACY_MODE, PrivacyViolationError, assembleVerdictFromAudit } from "@verdict/caseforge-sdk"
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { loadRoutes, resolveCandidate, opencodeProfileDir, routeLocation } from "../config.js"
import { verify } from "./verify.js"

/**
 * Independently verify the sealed manifest and persist manifest_verify.json.
 *
 * The agent's manifest_verify runs AFTER manifest_finalize seals the audit chain,
 * so its result is not written anywhere. caseforge re-verifies the signed
 * run.manifest.json itself with the toolkit's zero-dependency offline verifier
 * (`scripts/manifest-verify-offline.py`) — the "LLM is not the source of truth"
 * step for custody — and writes the result to manifest_verify.json.
 */
function finalizeManifestVerify(runDir: string): void {
  const manifest = join(runDir, "run.manifest.json")
  const out = join(runDir, "manifest_verify.json")
  if (!existsSync(manifest) || existsSync(out)) return
  const home = process.env.VERDICT_DFIR_HOME
  const verifier = home ? join(home, "scripts", "manifest-verify-offline.py") : ""
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

/** Newest VERDICT case dir under FINDEVIL_HOME/cases, if any. */
function findNewestCaseDir(dfirHome: string | undefined, findevilHome: string | undefined): string | undefined {
  const home = findevilHome ?? (dfirHome ? join(dfirHome, ".project-local", "findevil") : undefined)
  if (!home) return undefined
  const cases = join(home, "cases")
  if (!existsSync(cases)) return undefined
  let newest: { dir: string; mtime: number } | undefined
  for (const name of readdirSync(cases)) {
    const dir = join(cases, name)
    try {
      const st = statSync(dir)
      if (st.isDirectory() && (!newest || st.mtimeMs > newest.mtime)) newest = { dir, mtime: st.mtimeMs }
    } catch {
      /* skip */
    }
  }
  return newest?.dir
}

export interface InvestigateOpts {
  privacy?: PrivacyMode
  evidence?: EvidenceClass
  route?: string
  command?: string // opencode slash command to drive (default: triage)
  runDir?: string // explicit run/case dir to verify afterwards
  noVerify?: boolean
}

/** Pick the requested route, or the first route allowed under this context. */
function chooseRoute(opts: { privacy: PrivacyMode; evidenceClass: EvidenceClass; route?: string }): string | undefined {
  if (opts.route) return opts.route
  for (const id of Object.keys(loadRoutes())) {
    const resolved = resolveCandidate(id)
    if (!resolved) continue
    try {
      assertModelAllowed(resolved.candidate, { mode: opts.privacy, evidenceClass: opts.evidenceClass })
      return id
    } catch {
      /* not allowed under this mode; try next */
    }
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
  // Map a route to an opencode model ref + env.
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    OPENCODE_CONFIG: join(opencodeProfileDir(), "opencode.json"),
    OPENCODE_CONFIG_DIR: opencodeProfileDir(),
  }
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
  }

  const command = opts.command ?? "triage"
  // Drive the COMPLETE flow: the evidence-type playbook, then the /verdict
  // reason+seal phase. The run only counts as complete when the manifest is
  // finalized AND manifest_verify reports overall:true — otherwise the produced
  // case is a partial (unsealed) run and `caseforge verify` will reject it.
  const prompt =
    `Run a complete VERDICT investigation of the evidence at: ${evidencePath} .\n` +
    `1. Run the /${command} DFIR playbook (open the case, run the forensic MCP tools, cite each tool_call_id + output_sha256).\n` +
    `2. Then run the /verdict reason+seal phase to completion: verify each cited finding (verify_finding), judge (judge_findings, ACH), correlate (correlate_findings), report_qa, then SEAL — manifest_finalize (write run.manifest.json into the case directory) and manifest_verify.\n` +
    `Use only the VERDICT forensic MCP tools; operate read-only on evidence. Scope the verdict to SUSPICIOUS / INDETERMINATE / NO_EVIL. ` +
    `The run is NOT complete unless manifest_verify reports overall:true — do not stop before the manifest is finalized and verified.`

  console.error(`[caseforge] route=${routeId} model=${modelRef} privacy=${mode} evidence=${evidenceClass}`)
  console.error(`[caseforge] evidence=${evidencePath}`)

  const bin = process.env.VERDICT_BIN ?? "verdict"
  const runCode = await new Promise<number>((resolvePromise) => {
    const child = spawn(bin, ["run", "--agent", "verdict", "--model", modelRef, prompt], {
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
  const runDir = opts.runDir ?? findNewestCaseDir(process.env.VERDICT_DFIR_HOME, process.env.FINDEVIL_HOME)
  if (!runDir) {
    console.error("[caseforge] investigation finished; no run/case dir found to verify.")
    console.error("[caseforge] run `caseforge verify <run-dir>` on the produced case directory.")
    return runCode
  }
  // Independently confirm custody (writes manifest_verify.json), assemble the
  // structured verdict.json report from the audit chain, then validate.
  finalizeManifestVerify(runDir)
  await finalizeVerdictJson(runDir)
  console.error(`\n[caseforge] verifying produced run: ${runDir}`)
  const verifyCode = await verify([runDir])
  // Non-zero if the agent run failed OR the produced run does not verify.
  return runCode !== 0 ? runCode : verifyCode
}
