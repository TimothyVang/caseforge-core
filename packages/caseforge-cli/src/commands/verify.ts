/**
 * `caseforge verify <run-dir>` — validate VERDICT run artifacts + custody, and
 * check the custody of every finding in verdict.json (cited and replay-clean).
 */
import { validateRun, readVerdict, checkFindingsCustody } from "@verdict/caseforge-sdk"

export async function verify(args: string[]): Promise<number> {
  const runDir = args[0]
  if (!runDir) {
    console.error("usage: caseforge verify <run-dir>")
    return 2
  }

  const r = await validateRun(runDir)
  const mark = r.status === "complete" ? "OK" : r.status === "incomplete" ? "INCOMPLETE" : "CUSTODY-INVALID"
  console.log(`[${mark}] ${runDir}`)
  console.log(`  artifacts present: ${r.present.join(", ") || "(none)"}`)
  if (r.missing.length) console.log(`  artifacts missing: ${r.missing.join(", ")}`)
  console.log(`  manifest custody: ${r.custodyValid ? "verified" : "NOT verified"}`)

  // Findings custody (only when a verdict.json exists).
  const doc = await readVerdict(runDir)
  let findingsOk = true
  if (doc) {
    const fc = checkFindingsCustody(doc)
    findingsOk = fc.ok
    console.log(
      `  findings: ${fc.total} total, ${fc.cited} cited, ${fc.uncited} uncited, ${fc.replayVerified} replay-verified, ${fc.replayFailed} replay-failed`,
    )
    console.log(`  findings custody: ${fc.ok ? "OK — every anchored finding has an accepted citation and no replay failed" : "FAILED"}`)
    for (const f of fc.findings) {
      if (f.citation === "audit_record") console.log(`    - ${f.finding_id}: audit-record citation`)
      if (f.reason !== "ok" && f.reason.includes("vetoed")) console.log(`    ! ${f.finding_id}: ${f.reason}`)
      if (f.replayVerified === false) console.log(`    ! ${f.finding_id}: ${f.reason}`)
    }
  } else {
    console.log("  findings: (no verdict.json to check)")
  }

  console.log(`  ${r.detail}`)
  return r.status === "complete" && findingsOk ? 0 : 1
}
