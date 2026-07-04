import { readdir } from "node:fs/promises"
import { existsSync } from "node:fs"
import { join } from "node:path"
import { validateRun } from "@verdict/caseforge-sdk"
import type { RunStatus } from "@verdict/caseforge-sdk"

export interface RunEntry {
  dir: string
  status: RunStatus
  custodyValid: boolean
}

const looksLikeRun = (d: string): boolean =>
  existsSync(join(d, "run.manifest.json")) || existsSync(join(d, "verdict.json"))

/** Discover run directories under the given roots and validate each (read-only). */
export async function listRuns(roots: string[]): Promise<RunEntry[]> {
  const entries: RunEntry[] = []
  for (const root of roots) {
    if (!existsSync(root)) continue
    let names: string[]
    try {
      names = (await readdir(root)).sort()
    } catch {
      continue
    }
    for (const name of names) {
      const dir = join(root, name)
      if (!looksLikeRun(dir)) continue
      const v = await validateRun(dir)
      entries.push({ dir, status: v.status, custodyValid: v.custodyValid })
    }
  }
  return entries
}
