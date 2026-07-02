/** `caseforge doctor` — environment + config prerequisite check. */
import { existsSync } from "node:fs"
import { join } from "node:path"
import { execFileSync } from "node:child_process"
import { DEFAULT_PRIVACY_MODE } from "@verdict/caseforge-sdk"
import { configsDir, loadRoutes, opencodeProfileDir, routeLocation } from "../config.js"

function has(cmd: string): boolean {
  try {
    execFileSync("bash", ["-lc", `command -v ${cmd}`], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

async function reachable(baseUrl: string): Promise<boolean> {
  const candidates = [baseUrl.replace(/\/v1\/?$/, "/api/tags"), `${baseUrl.replace(/\/$/, "")}/models`]
  for (const url of candidates) {
    try {
      const ctl = new AbortController()
      const t = setTimeout(() => ctl.abort(), 2500)
      const res = await fetch(url, { signal: ctl.signal }).catch(() => undefined)
      clearTimeout(t)
      if (res) return true
    } catch {
      /* try next */
    }
  }
  return false
}

export async function doctor(): Promise<number> {
  let warn = 0
  const ok = (m: string) => console.log(`  [ok]   ${m}`)
  const miss = (m: string) => {
    console.log(`  [MISS] ${m}`)
    warn++
  }

  console.log("caseforge doctor\n")
  console.log(`privacy default: ${DEFAULT_PRIVACY_MODE} (real evidence stays local unless overridden)\n`)

  // agent runtime
  has(process.env.VERDICT_BIN ?? "verdict") ? ok("verdict binary on PATH") : miss("verdict binary not on PATH (build verdict-opencode)")

  // locked opencode profile
  existsSync(join(opencodeProfileDir(), "opencode.json"))
    ? ok(`locked opencode profile: ${opencodeProfileDir()}`)
    : miss("configs/opencode/opencode.json missing")

  // VERDICT MCP toolkit
  const dfirHome = process.env.VERDICT_DFIR_HOME
  if (dfirHome && existsSync(join(dfirHome, "scripts/run-mcp-rust.sh"))) {
    ok(`VERDICT toolkit (VERDICT_DFIR_HOME): ${dfirHome}`)
    existsSync(join(dfirHome, "target/release/findevil-mcp"))
      ? ok("findevil-mcp release binary present")
      : miss("findevil-mcp not prebuilt (cargo build --release -p findevil-mcp)")
    has("uv") ? ok("uv present (findevil-agent-mcp)") : miss("uv missing (findevil-agent-mcp)")
  } else {
    miss("VERDICT_DFIR_HOME not set to a toolkit checkout with scripts/run-mcp-rust.sh")
  }

  // routes + local endpoints
  const routes = loadRoutes()
  const ids = Object.keys(routes)
  ids.length ? ok(`${ids.length} routes in ${join(configsDir(), "model-routes.yaml")}`) : miss("no routes in configs/model-routes.yaml")
  for (const [id, r] of Object.entries(routes)) {
    if (routeLocation(r) === "local" && r.base_url) {
      ;(await reachable(r.base_url)) ? ok(`local route '${id}' endpoint reachable (${r.base_url})`) : miss(`local route '${id}' endpoint down (${r.base_url})`)
    }
  }

  console.log()
  console.log(warn === 0 ? "All prerequisites satisfied." : `${warn} item(s) need attention above.`)
  return warn === 0 ? 0 : 1
}
