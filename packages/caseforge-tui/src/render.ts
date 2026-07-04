import type { CaseView, CoverageRow, AuditRecord } from "./load.js"
import type { FindingCustody } from "@verdict/caseforge-sdk"
import type { RunEntry } from "./picker.js"

const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"
const DIM = "\x1b[2m"
const rgb = (r: number, g: number, b: number): string => `\x1b[38;2;${r};${g};${b}m`
const SEAFOAM = rgb(115, 217, 194)
const BUTTER = rgb(255, 215, 106)
const COBALT = rgb(120, 140, 255)
const CORAL = rgb(255, 98, 87)
const LILAC = rgb(184, 168, 255)

function tierColor(c?: string): string {
  const t = (c ?? "").toUpperCase()
  if (t === "CONFIRMED") return SEAFOAM
  if (t === "INFERRED") return BUTTER
  return COBALT
}
function verdictColor(v?: string): string {
  const w = (v ?? "").toUpperCase()
  if (w === "SUSPICIOUS") return CORAL
  if (w === "NO_EVIL") return SEAFOAM
  return BUTTER
}
function light(ok: boolean | undefined): string {
  if (ok === true) return `${SEAFOAM}●${RESET}`
  if (ok === false) return `${CORAL}●${RESET}`
  return `${DIM}○${RESET}`
}
function mark(b?: boolean): string {
  if (b === true) return `${SEAFOAM}✓${RESET}`
  if (b === false) return `${DIM}–${RESET}`
  return `${DIM}?${RESET}`
}
const NOT_PRODUCED = `${DIM}not produced by this run${RESET}`

export function renderHeader(v: CaseView): string {
  const verd = v.verdict?.verdict ?? "(no verdict.json)"
  return [
    `${LILAC}${BOLD}VERDICT · caseforge workbench${RESET}   ${DIM}read-only · presentation only${RESET}`,
    `${BOLD}${verdictColor(v.verdict?.verdict)}${verd}${RESET}   ${DIM}case ${v.verdict?.case_id ?? v.runDir}${RESET}`,
    `custody:  recorded ${light(v.recordedManifestOverall)} manifest_verify   |   re-verified now ${light(v.validation.custodyValid)} ${DIM}(${v.validation.status})${RESET}`,
    `${DIM}${v.validation.detail}${RESET}`,
  ].join("\n")
}

function custodyOf(report: CaseView["custody"], fid?: string): FindingCustody | undefined {
  if (!report || !fid) return undefined
  return report.findings.find((f) => f.finding_id === fid)
}

export function renderFindings(v: CaseView): string {
  const head = `${LILAC}${BOLD}FINDINGS${RESET}`
  const findings = v.verdict?.findings ?? []
  if (findings.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = findings.map((f) => {
    const conf = (f.confidence ?? "?").toString()
    const tech = (f["mitre_technique"] as string | undefined) ?? (f["named_technique"] as string | undefined) ?? "unmapped"
    const desc = ((f.description ?? "") as string).slice(0, 64)
    const cust = custodyOf(v.custody, f.finding_id)
    const custStr = cust
      ? `${cust.cited ? SEAFOAM + "cited" : CORAL + "UNCITED"}${RESET} ${DIM}tool_call_id ${f.tool_call_id ?? "?"}${RESET}`
      : `${DIM}tool_call_id ${f.tool_call_id ?? "?"}${RESET}`
    return [
      `  ${tierColor(conf)}●${RESET} ${BOLD}${tech}${RESET} ${DIM}${conf}${RESET}`,
      `      ${desc}`,
      `      ${custStr}`,
    ].join("\n")
  })
  return `${head}\n${rows.join("\n")}`
}

export function renderCoverage(v: CaseView): string {
  const head = `${LILAC}${BOLD}COVERAGE${RESET}`
  if (v.coverage.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = v.coverage.map(
    (c: CoverageRow) =>
      `  ${c.artifact_class.padEnd(14)} avail ${mark(c.available)}  attempted ${mark(c.attempted)}  parsed ${mark(c.parsed)}`,
  )
  return `${head}\n${rows.join("\n")}`
}

export function renderAudit(v: CaseView): string {
  const head = `${LILAC}${BOLD}AUDIT TAIL${RESET}`
  if (v.audit.length === 0) return `${head}\n  ${DIM}no audit.jsonl records${RESET}`
  const chain = v.chainOk ? `${SEAFOAM}chain linkage OK${RESET}` : `${CORAL}chain linkage BROKEN${RESET}`
  const tail = v.audit
    .slice(-5)
    .map((r: AuditRecord) => `  ${DIM}#${r.seq ?? "?"}${RESET} ${(r.kind ?? "?").padEnd(20)} ${DIM}${r.ts ?? ""}${RESET}`)
  return `${head}  ${DIM}${v.audit.length} records ·${RESET} ${chain}\n${tail.join("\n")}`
}

export function renderTimeline(v: CaseView): string {
  const head = `${LILAC}${BOLD}TIMELINE${RESET}`
  if (v.timeline.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = v.timeline
    .slice(0, 8)
    .map((e) => `  ${tierColor(e.confidence)}●${RESET} ${DIM}${e.ts ?? "?"}${RESET} ${BOLD}${e.technique ?? "-"}${RESET} ${(e.summary ?? "").slice(0, 48)}`)
  const more = v.timeline.length > 8 ? `\n  ${DIM}… ${v.timeline.length - 8} more events${RESET}` : ""
  return `${head}  ${DIM}${v.timeline.length} events${RESET}\n${rows.join("\n")}${more}`
}

export function renderPicker(entries: RunEntry[]): string {
  const head = `${LILAC}${BOLD}CASES${RESET}`
  if (entries.length === 0) return `${head}\n  ${DIM}no run directories found${RESET}`
  const rows = entries.map((e, i) => {
    const l = e.status === "complete" && e.custodyValid ? SEAFOAM : e.status === "custody-invalid" ? CORAL : BUTTER
    return `  ${DIM}${String(i + 1).padStart(2)}${RESET} ${l}●${RESET} ${e.status.padEnd(16)} ${DIM}${e.dir}${RESET}`
  })
  return `${head}  ${DIM}${entries.length}${RESET}\n${rows.join("\n")}`
}

export function renderScreen(v: CaseView): string {
  return [renderHeader(v), renderFindings(v), renderTimeline(v), renderCoverage(v), renderAudit(v)].join("\n\n")
}
