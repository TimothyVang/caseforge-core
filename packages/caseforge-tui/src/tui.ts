#!/usr/bin/env node
import { loadCase } from "./load.js"
import { renderScreen } from "./render.js"

const runDir = process.argv[2]
if (!runDir) {
  process.stderr.write("usage: caseforge-tui <run-dir>\n")
  process.exit(2)
}
const view = await loadCase(runDir)
process.stdout.write(renderScreen(view) + "\n")
