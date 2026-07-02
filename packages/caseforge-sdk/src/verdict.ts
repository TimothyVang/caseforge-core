/**
 * VERDICT verdict.json ingestion + findings custody check.
 *
 * The VERDICT toolkit emits a rich verdict.json whose findings each carry a
 * `tool_call_id` (required — its verifier vetoes if absent) and the verifier's
 * replay result (`replay_matched`). caseforge ingests those real findings and
 * enforces the default security rule independently of the LLM: every reported
 * finding must be cited (tool_call_id) and, when the verifier replayed it, the
 * replay must have matched. Uncited or replay-failed findings are flagged.
 */
import { readFile } from "node:fs/promises"
import { join } from "node:path"

export interface VerdictFinding {
  finding_id?: string
  tool_call_id?: string
  confidence?: string
  description?: string
  verdict?: string
  replay_matched?: boolean
  replay_record_sha256?: string
  replay_actual_sha256?: string
  [k: string]: unknown
}

export interface VerdictDoc {
  verdict?: string
  case_id?: string
  findings?: VerdictFinding[]
  [k: string]: unknown
}

/** Read and parse a run's verdict.json (undefined if absent/unreadable). */
export async function readVerdict(runDir: string): Promise<VerdictDoc | undefined> {
  try {
    return JSON.parse(await readFile(join(runDir, "verdict.json"), "utf8")) as VerdictDoc
  } catch {
    return undefined
  }
}

export interface FindingCustody {
  finding_id: string
  cited: boolean
  replayVerified: boolean | null // null = verifier did not replay this finding
  reason: string
}

export interface FindingsCustodyReport {
  total: number
  cited: number
  uncited: number
  replayVerified: number
  replayFailed: number
  ok: boolean
  findings: FindingCustody[]
}

/** A finding is anchored (must be tool-cited) unless it is a HYPOTHESIS. */
function isAnchored(f: VerdictFinding): boolean {
  const c = (f.confidence ?? "").toUpperCase()
  return c === "CONFIRMED" || c === "INFERRED"
}

/**
 * Verify the custody of every finding in a run's verdict.json using the
 * toolkit's own signals. `ok` is true only when no anchored finding is uncited
 * and no replayed finding failed its replay.
 */
export function checkFindingsCustody(doc: VerdictDoc | undefined): FindingsCustodyReport {
  const findings = doc?.findings ?? []
  const results: FindingCustody[] = findings.map((f, i) => {
    const id = f.finding_id ?? `#${i}`
    const cited = typeof f.tool_call_id === "string" && f.tool_call_id.trim() !== ""
    const replayVerified = typeof f.replay_matched === "boolean" ? f.replay_matched : null
    let reason = "ok"
    if (isAnchored(f) && !cited) reason = "anchored finding is uncited (no tool_call_id) — vetoed"
    else if (replayVerified === false) reason = "verifier replay did not match — custody failed"
    else if (!cited) reason = "unanchored (hypothesis) — no tool_call_id required"
    return { finding_id: id, cited, replayVerified, reason }
  })
  const uncitedAnchored = results.some((r, i) => isAnchored(findings[i]!) && !r.cited)
  const replayFailed = results.some((r) => r.replayVerified === false)
  return {
    total: results.length,
    cited: results.filter((r) => r.cited).length,
    uncited: results.filter((r) => !r.cited).length,
    replayVerified: results.filter((r) => r.replayVerified === true).length,
    replayFailed: results.filter((r) => r.replayVerified === false).length,
    ok: !uncitedAnchored && !replayFailed,
    findings: results,
  }
}
