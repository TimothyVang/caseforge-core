import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"
import { spawnSync } from "node:child_process"
import { repoRoot } from "./config.js"

const OPENAI_PROVIDER_ID = "openai"
const BROWSER_METHOD = "ChatGPT Pro/Plus (browser)"
const HEADLESS_METHOD = "ChatGPT Pro/Plus (headless)"

export interface ChatGptOAuthStatus {
  ok: boolean
  authPath: string
  source: "env" | "file"
  reason?: string
  credentialType?: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function opencodeAuthPath(): string {
  return join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"), "opencode", "auth.json")
}

export function verdictLauncherPath(env: NodeJS.ProcessEnv = process.env): string {
  const local = join(repoRoot(), "bin", "verdict")
  if (existsSync(local)) return local
  return env.VERDICT_BIN ?? "verdict"
}

function readAuthRecord(): { source: "env" | "file"; authPath: string; record?: Record<string, unknown>; reason?: string } {
  const authPath = opencodeAuthPath()
  const content = process.env.OPENCODE_AUTH_CONTENT
  if (content) {
    try {
      const parsed: unknown = JSON.parse(content)
      return isRecord(parsed) ? { source: "env", authPath, record: parsed } : { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not an object" }
    } catch {
      return { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not valid JSON" }
    }
  }

  if (!existsSync(authPath)) return { source: "file", authPath, reason: "no opencode auth.json found" }
  try {
    const parsed: unknown = JSON.parse(readFileSync(authPath, "utf8"))
    return isRecord(parsed) ? { source: "file", authPath, record: parsed } : { source: "file", authPath, reason: "opencode auth.json is not an object" }
  } catch {
    return { source: "file", authPath, reason: "opencode auth.json is not valid JSON" }
  }
}

export function chatGptOAuthStatus(): ChatGptOAuthStatus {
  const loaded = readAuthRecord()
  if (!loaded.record) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: loaded.reason ?? "OpenAI OAuth credential is missing",
    }
  }

  const credential = loaded.record[OPENAI_PROVIDER_ID]
  if (!isRecord(credential)) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: "OpenAI credential is missing",
    }
  }

  const type = typeof credential.type === "string" ? credential.type : undefined
  if (type !== "oauth") {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: type ? `OpenAI credential is '${type}', not ChatGPT OAuth` : "OpenAI credential has no type",
    }
  }

  if (typeof credential.refresh !== "string" || credential.refresh.length === 0) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: "OpenAI OAuth credential has no refresh token",
    }
  }

  return {
    ok: true,
    authPath: loaded.authPath,
    source: loaded.source,
    credentialType: type,
  }
}

export function chatGptOAuthLogin(method: string | boolean | undefined): number {
  const label = method === "browser" ? BROWSER_METHOD : HEADLESS_METHOD
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "login", "--provider", OPENAI_PROVIDER_ID, "--method", label], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function chatGptOAuthLogout(): number {
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "logout", OPENAI_PROVIDER_ID], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function printChatGptOAuthSetup(): void {
  console.error("Run: caseforge auth login --method headless")
  console.error("or:  caseforge auth login --method browser")
}
