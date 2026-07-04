import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { validateRun, readVerdict, checkFindingsCustody } from "@verdict/caseforge-sdk"
import type { RunValidation, VerdictDoc, FindingsCustodyReport } from "@verdict/caseforge-sdk"

export interface CoverageRow {
  artifact_class: string
  available?: boolean
  attempted?: boolean
  parsed?: boolean
  supported?: boolean
}

export interface AuditRecord {
  seq?: number
  kind?: string
  prev_hash?: string
  ts?: string
  tool_call_id?: string
}

export interface CaseView {
  runDir: string
  validation: RunValidation
  recordedManifestOverall: boolean | undefined
  verdict: VerdictDoc | undefined
  custody: FindingsCustodyReport | undefined
  coverage: CoverageRow[]
  audit: AuditRecord[]
  chainOk: boolean
}

async function readJson(path: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8"))
  } catch {
    return undefined
  }
}

function readCoverage(raw: unknown): CoverageRow[] {
  if (!raw || typeof raw !== "object") return []
  const o = raw as Record<string, unknown>
  const rows = (o.classes ?? o.targets ?? o.coverage) as unknown
  if (!Array.isArray(rows)) return []
  return rows
    .filter((r): r is Record<string, unknown> => Boolean(r) && typeof r === "object")
    .map((r) => ({
      artifact_class: String(r.artifact_class ?? r.class ?? r.name ?? "?"),
      available: r.available as boolean | undefined,
      attempted: r.attempted as boolean | undefined,
      parsed: r.parsed as boolean | undefined,
      supported: r.supported as boolean | undefined,
    }))
}

async function readAudit(runDir: string): Promise<AuditRecord[]> {
  let text: string
  try {
    text = await readFile(join(runDir, "audit.jsonl"), "utf8")
  } catch {
    return []
  }
  const out: AuditRecord[] = []
  for (const line of text.split("\n")) {
    const t = line.trim()
    if (!t) continue
    try {
      const e = JSON.parse(t) as Record<string, unknown>
      out.push({
        seq: typeof e.seq === "number" ? e.seq : undefined,
        kind: typeof e.kind === "string" ? e.kind : undefined,
        prev_hash: typeof e.prev_hash === "string" ? e.prev_hash : undefined,
        ts: typeof e.ts === "string" ? e.ts : undefined,
        tool_call_id:
          (e.payload as Record<string, unknown> | undefined)?.tool_call_id as string | undefined,
      })
    } catch {
      /* skip malformed line */
    }
  }
  return out
}

/** Structural chain check: seq strictly increases and every record after the
 * first carries a prev_hash. NOT the cryptographic Merkle re-derivation (that
 * lives in the Rust verifier / `caseforge verify`); this is a cheap in-view
 * linkage sanity check shown alongside the recorded, verified custody status. */
function chainStructurallyOk(records: AuditRecord[]): boolean {
  if (records.length === 0) return false
  let lastSeq = -Infinity
  for (let i = 0; i < records.length; i++) {
    const r = records[i]!
    if (typeof r.seq === "number") {
      if (r.seq <= lastSeq) return false
      lastSeq = r.seq
    }
    if (i > 0 && !r.prev_hash) return false
  }
  return true
}

/** Read-only assembly: never mutates the run dir. Re-verifies custody live. */
export async function loadCase(runDir: string): Promise<CaseView> {
  const validation = await validateRun(runDir)
  const mv = (await readJson(join(runDir, "manifest_verify.json"))) as Record<string, unknown> | undefined
  const recordedManifestOverall = mv ? (mv.overall as boolean | undefined) : undefined
  const verdict = await readVerdict(runDir)
  const custody = verdict ? checkFindingsCustody(verdict) : undefined
  const coverage = readCoverage(await readJson(join(runDir, "coverage_manifest.json")))
  const audit = await readAudit(runDir)
  return { runDir, validation, recordedManifestOverall, verdict, custody, coverage, audit, chainOk: chainStructurallyOk(audit) }
}
