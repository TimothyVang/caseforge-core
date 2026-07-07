import { chatGptOAuthLogin, chatGptOAuthLogout, chatGptOAuthStatus } from "../chatgpt-auth.js"

type Flags = Record<string, string | boolean>

function usage(): void {
  console.log(`caseforge auth — ChatGPT subscription OAuth for the embedded VERDICT engine

  auth status                 show whether ChatGPT OAuth is configured
  auth login [--method M]     log in with ChatGPT Pro/Plus OAuth (M: headless|browser)
  auth logout                 remove the OpenAI provider credential through verdict auth

This does not configure OPENAI_API_KEY or OpenAI Platform API billing.`)
}

export function auth(args: string[], flags: Flags): number {
  const subcommand = args[0] ?? "status"
  switch (subcommand) {
    case "status": {
      const status = chatGptOAuthStatus()
      if (status.ok) {
        console.log(`  [ok]   ChatGPT OAuth credential present for provider 'openai' (${status.source})`)
      } else {
        console.log(`  [MISS] ChatGPT OAuth credential missing: ${status.reason}`)
        console.log(`         checked: ${status.authPath}`)
      }
      if (process.env.OPENAI_API_KEY) {
        console.log("  [info] OPENAI_API_KEY is set, but route 'chatgpt-oauth' ignores API keys.")
      }
      return status.ok ? 0 : 1
    }
    case "login":
      return chatGptOAuthLogin(flags.method)
    case "logout":
      return chatGptOAuthLogout()
    case "help":
    case "--help":
    case "-h":
      usage()
      return 0
    default:
      console.error(`unknown auth command: ${subcommand}`)
      usage()
      return 2
  }
}
