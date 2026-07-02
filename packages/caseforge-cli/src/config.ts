/**
 * Load caseforge configs (model routes + provider capabilities) and resolve a
 * route into a privacy-aware ModelCandidate the SDK router can evaluate.
 */
import { readFileSync, existsSync } from "node:fs"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { parse as parseYaml } from "yaml"
import type { ModelCandidate, ProviderLocation } from "@verdict/caseforge-sdk"

export interface RouteConfig {
  provider: string
  model: string
  base_url?: string
  tool_calling?: boolean | "unknown"
  /** Router contract: cloud-tainted if any listed location is "cloud". */
  privacy_locations: ProviderLocation[]
  network?: boolean
}

/** Collapse privacy_locations to a single location (fail-closed to cloud). */
export function routeLocation(route: RouteConfig): ProviderLocation {
  return route.privacy_locations?.includes("cloud") ? "cloud" : "local"
}

/**
 * Repo root: walk up from this module until a directory containing
 * `configs/model-routes.yaml` is found. Robust to running from `src` or `dist`.
 */
export function repoRoot(): string {
  let dir = resolve(fileURLToPath(import.meta.url), "..")
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "configs", "model-routes.yaml"))) return dir
    const parent = resolve(dir, "..")
    if (parent === dir) break
    dir = parent
  }
  // Fallback to CWD (supports CASEFORGE_CONFIG_DIR override in configsDir()).
  return process.cwd()
}

export function configsDir(): string {
  return process.env.CASEFORGE_CONFIG_DIR ?? join(repoRoot(), "configs")
}

function loadYaml<T>(name: string): T | undefined {
  const path = join(configsDir(), name)
  if (!existsSync(path)) return undefined
  return parseYaml(readFileSync(path, "utf8")) as T
}

/** All named routes from model-routes.yaml (routes: { id: {...} }). */
export function loadRoutes(): Record<string, RouteConfig> {
  const doc = loadYaml<{ routes?: Record<string, RouteConfig> }>("model-routes.yaml")
  return doc?.routes ?? {}
}

/** Resolve a route id into a ModelCandidate for the privacy router. */
export function resolveCandidate(routeId: string): { candidate: ModelCandidate; route: RouteConfig } | undefined {
  const routes = loadRoutes()
  const route = routes[routeId]
  if (!route) return undefined
  return {
    route,
    candidate: {
      id: `${routeId}`,
      location: routeLocation(route),
      network: route.network,
    },
  }
}

/** The locked opencode profile directory (agents/commands/skill + config). */
export function opencodeProfileDir(): string {
  return join(configsDir(), "opencode")
}
