/** `caseforge verify <run-dir>` — validate VERDICT run artifacts + custody. */
import { validateRun } from "@verdict/caseforge-sdk"

export async function verify(args: string[]): Promise<number> {
  const runDir = args[0]
  if (!runDir) {
    console.error("usage: caseforge verify <run-dir>")
    return 2
  }
  const r = await validateRun(runDir)
  const mark = r.status === "complete" ? "OK" : r.status === "incomplete" ? "INCOMPLETE" : "CUSTODY-INVALID"
  console.log(`[${mark}] ${runDir}`)
  console.log(`  present: ${r.present.join(", ") || "(none)"}`)
  if (r.missing.length) console.log(`  missing: ${r.missing.join(", ")}`)
  console.log(`  custody: ${r.custodyValid ? "verified" : "NOT verified"}`)
  console.log(`  ${r.detail}`)
  // Exit non-zero unless the run is complete AND custody verified.
  return r.status === "complete" ? 0 : 1
}
