/**
 * `caseforge investigate <evidence-path>` — run a privacy-gated DFIR
 * investigation with the VERDICT agent + forensic MCP tools.
 *
 * The privacy router decides whether the chosen route may be used for the
 * evidence class BEFORE any model is contacted. In local-only mode a cloud
 * route is refused outright — no evidence leaves the host.
 */
import { spawn } from "node:child_process"
import { existsSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"
import { assertModelAllowed, DEFAULT_PRIVACY_MODE, PrivacyViolationError } from "@verdict/caseforge-sdk"
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { loadRoutes, resolveCandidate, opencodeProfileDir, routeLocation } from "../config.js"
import { verify } from "./verify.js"

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
  const prompt = `Run the /${command} DFIR playbook on the evidence at: ${evidencePath} . Use only the VERDICT forensic MCP tools; cite each tool_call_id and output hash. Report findings scoped to SUSPICIOUS / INDETERMINATE / NO_EVIL.`

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
  console.error(`\n[caseforge] verifying produced run: ${runDir}`)
  const verifyCode = await verify([runDir])
  // Non-zero if the agent run failed OR the produced run does not verify.
  return runCode !== 0 ? runCode : verifyCode
}
