/**
 * VERDICT run-artifact validator + custody verification.
 *
 * A completed VERDICT run must produce a fixed set of artifacts. Missing any of
 * them marks the run INCOMPLETE. A present-but-failed manifest verification
 * marks the run CUSTODY-INVALID. Only when all artifacts exist and the manifest
 * verifies is the run COMPLETE.
 */
import { readFile } from "node:fs/promises"
import { existsSync } from "node:fs"
import { join } from "node:path"

/**
 * Artifacts every VERDICT run must emit. `coverage_manifest.json` is special:
 * the toolkit manifests coverage INSIDE verdict.json (attack_coverage /
 * case_completeness) rather than as a separate file, so the coverage
 * requirement is satisfied either way (see `coverageSatisfied`).
 */
export const REQUIRED_ARTIFACTS = [
  "verdict.json",
  "coverage_manifest.json",
  "run.manifest.json",
  "manifest_verify.json",
  "audit.jsonl",
] as const

/** Hard files that must exist on disk (coverage handled separately). */
const HARD_REQUIRED = ["verdict.json", "run.manifest.json", "manifest_verify.json", "audit.jsonl"] as const

export type RunStatus = "complete" | "incomplete" | "custody-invalid"

export interface RunValidation {
  status: RunStatus
  present: string[]
  missing: string[]
  custodyValid: boolean
  detail: string
}

/** Read a JSON file, returning undefined on any read/parse error. */
async function readJson(path: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8"))
  } catch {
    return undefined
  }
}

/**
 * Interpret manifest_verify.json. Fail-closed: unless it clearly says the
 * manifest verified, custody is treated as invalid.
 */
function manifestVerified(v: unknown): boolean {
  if (!v || typeof v !== "object") return false
  const o = v as Record<string, unknown>
  // `overall` is VERDICT's own top-level pass flag in manifest_verify.json.
  if (o.overall === true || o.ok === true || o.verified === true || o.valid === true) return true
  if (typeof o.status === "string" && ["ok", "valid", "verified", "pass"].includes(o.status.toLowerCase())) return true
  return false
}

/** Coverage is satisfied by a coverage_manifest.json OR embedded in verdict.json. */
async function coverageSatisfied(runDir: string): Promise<boolean> {
  if (existsSync(join(runDir, "coverage_manifest.json"))) return true
  const verdict = (await readJson(join(runDir, "verdict.json"))) as Record<string, unknown> | undefined
  return Boolean(verdict && (verdict.attack_coverage || verdict.case_completeness))
}

/** Validate the artifacts of a run directory. */
export async function validateRun(runDir: string): Promise<RunValidation> {
  const present: string[] = []
  const missing: string[] = []
  for (const name of HARD_REQUIRED) {
    if (existsSync(join(runDir, name))) present.push(name)
    else missing.push(name)
  }
  const hasCoverage = await coverageSatisfied(runDir)
  if (existsSync(join(runDir, "coverage_manifest.json"))) present.push("coverage_manifest.json")
  else if (!hasCoverage) missing.push("coverage_manifest.json (or coverage embedded in verdict.json)")

  // Always evaluate manifest custody when the file is present, so reporting is
  // accurate even for an otherwise-incomplete run.
  const custodyValid = manifestVerified(await readJson(join(runDir, "manifest_verify.json")))

  if (missing.length > 0) {
    return { status: "incomplete", present, missing, custodyValid, detail: `run incomplete — missing ${missing.join(", ")}` }
  }
  if (!custodyValid) {
    return {
      status: "custody-invalid",
      present,
      missing,
      custodyValid: false,
      detail: "custody invalid — manifest_verify.json did not confirm verification",
    }
  }
  return { status: "complete", present, missing, custodyValid: true, detail: "run complete and custody verified" }
}

// --- per-finding custody verification -------------------------------------

export interface AuditEntry {
  tool_call_id?: string
  id?: string
  call_id?: string
  output_sha256?: string
  sha256?: string
  output_hash?: string
  [k: string]: unknown
}

/** Load hash-chained audit.jsonl into entries indexed by tool_call_id. */
export async function loadAudit(runDir: string): Promise<Map<string, AuditEntry>> {
  const index = new Map<string, AuditEntry>()
  let text: string
  try {
    text = await readFile(join(runDir, "audit.jsonl"), "utf8")
  } catch {
    return index
  }
  for (const line of text.split("\n")) {
    const t = line.trim()
    if (!t) continue
    try {
      const e = JSON.parse(t) as AuditEntry
      const key = e.tool_call_id ?? e.id ?? e.call_id
      if (typeof key === "string") index.set(key, e)
    } catch {
      /* skip malformed line */
    }
  }
  return index
}

export interface CitationCheck {
  tool_call_id: string
  found: boolean
  hashMatch: boolean
  reason: string
}

/**
 * Verify that each evidence citation's tool_call_id exists in the audit chain
 * and its output_sha256 matches — the concrete "LLM is not the source of truth"
 * check. Fail-closed: a citation not found in the audit is not verified.
 */
export function verifyCitations(
  citations: Array<{ tool_call_id: string; output_sha256: string }>,
  audit: Map<string, AuditEntry>,
): { verified: boolean; checks: CitationCheck[] } {
  const checks = citations.map((c) => {
    const entry = audit.get(c.tool_call_id)
    if (!entry) {
      return { tool_call_id: c.tool_call_id, found: false, hashMatch: false, reason: "tool_call_id not in audit chain" }
    }
    const auditHash = (entry.output_sha256 ?? entry.sha256 ?? entry.output_hash ?? "").toLowerCase()
    const hashMatch = auditHash !== "" && auditHash === c.output_sha256.toLowerCase()
    return {
      tool_call_id: c.tool_call_id,
      found: true,
      hashMatch,
      reason: hashMatch ? "verified" : "output_sha256 does not match audit entry",
    }
  })
  return { verified: checks.length > 0 && checks.every((c) => c.found && c.hashMatch), checks }
}
