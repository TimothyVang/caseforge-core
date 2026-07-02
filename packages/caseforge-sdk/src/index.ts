// @verdict/caseforge-sdk — headless DFIR agentic core.
// opencode SDK controller + privacy router + structured findings + custody.

export { VerdictHarness, DEFAULT_THEME, DEFAULT_BINARY } from "./harness.js"
export { renderMasthead, printMasthead } from "./masthead.js"
export type {
  AskOptions,
  ModelRef,
  SessionHandle,
  TuiLaunchOptions,
  VerdictHarnessOptions,
  VerdictMcpConfig,
  VerdictMcpLocal,
  VerdictMcpRemote,
} from "./types.js"

export {
  DEFAULT_PRIVACY_MODE,
  decideModel,
  assertModelAllowed,
  PrivacyViolationError,
  redact,
} from "./privacy.js"
export type {
  PrivacyMode,
  ProviderLocation,
  EvidenceClass,
  ModelCandidate,
  PrivacyContext,
  PrivacyDecision,
  RedactionOptions,
} from "./privacy.js"

export { Finding, EvidenceCitation, VerdictWord, validateFinding, validateFindings } from "./finding.js"
export type { ValidationResult } from "./finding.js"

export {
  REQUIRED_ARTIFACTS,
  validateRun,
  loadAudit,
  verifyCitations,
} from "./artifacts.js"
export type { RunStatus, RunValidation, AuditEntry, CitationCheck } from "./artifacts.js"

export { readVerdict, checkFindingsCustody, assembleVerdictFromAudit } from "./verdict.js"
export type { VerdictDoc, VerdictFinding, FindingCustody, FindingsCustodyReport, AssembledVerdict } from "./verdict.js"
