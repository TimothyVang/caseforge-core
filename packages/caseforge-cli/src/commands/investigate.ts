/**
 * `caseforge investigate <evidence-path>` — run a privacy-gated DFIR
 * investigation with the VERDICT agent + forensic MCP tools.
 *
 * The privacy router decides whether the chosen route may be used for the
 * evidence class BEFORE any model is contacted. In local-only mode a cloud
 * route is refused outright — no evidence leaves the host.
 */
import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { join } from "node:path"
import { assertModelAllowed, DEFAULT_PRIVACY_MODE, PrivacyViolationError } from "@verdict/caseforge-sdk"
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { loadRoutes, resolveCandidate, opencodeProfileDir, routeLocation } from "../config.js"

export interface InvestigateOpts {
  privacy?: PrivacyMode
  evidence?: EvidenceClass
  route?: string
  command?: string // opencode slash command to drive (default: triage)
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
    env.VERDICT_LLM_BASEURL = route.base_url ?? "http://localhost:11434/v1"
    env.VERDICT_LLM_APIKEY = env.VERDICT_LLM_APIKEY ?? "local"
    env.VERDICT_LLM_MODEL = route.model
  } else {
    // cloud provider handled by opencode's built-in catalog + auth
    modelRef = `${route.provider}/${route.model}`
  }

  const command = opts.command ?? "triage"
  const prompt = `Run the /${command} DFIR playbook on the evidence at: ${evidencePath} . Use only the VERDICT forensic MCP tools; cite each tool_call_id and output hash. Report findings scoped to SUSPICIOUS / INDETERMINATE / NO_EVIL.`

  console.error(`[caseforge] route=${routeId} model=${modelRef} privacy=${mode} evidence=${evidenceClass}`)
  console.error(`[caseforge] evidence=${evidencePath}`)

  const bin = process.env.VERDICT_BIN ?? "verdict"
  return await new Promise<number>((resolvePromise) => {
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
}
