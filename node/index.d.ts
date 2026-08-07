export interface RequestEvent {
  method: string;
  path: string;
  status: number;
  authenticated?: boolean;
}
export interface SentinelConfig {
  /** Your app install token (nsk_…). */
  token: string;
  /** Override the ingest endpoint (defaults to the hosted Nemesis Shield). */
  endpoint?: string;
  /** Decide whether a request was authenticated. Defaults to presence of Authorization/Cookie. */
  authed?: (req: any) => boolean;
  /** Collapse path IDs to shapes (/orders/123 -> /orders/{int}). Default true. */
  shapePaths?: boolean;
}
export interface LLMExchange {
  prompt: string;
  system?: string;
  response?: string;
  tools?: string[];
  allowedTools?: string[];
}
export interface LLMVerdict {
  blocked: boolean;
  severity: "none" | "medium" | "high";
  kind?: "prompt_injection" | "ml_prompt_injection";
  score: number;
  owasp?: string;
}
export function sentinel(config: SentinelConfig): (req: any, res: any, next: (err?: unknown) => void) => void;
export function report(token: string, events: RequestEvent[], opts?: { endpoint?: string }): Promise<void>;
export function reportLLM(token: string, exchange: LLMExchange, opts?: { endpoint?: string }): Promise<void>;
export function pathShape(path: string): string;

/** OWASP-LLM prompt-injection check (regex + HashLR ML). `enforce` sets `blocked` when an attack is found. */
export function guardLLM(prompt: string, enforce?: boolean): LLMVerdict;
/** Raw HashLR probability (0..1) that `text` is a prompt-injection / jailbreak attempt. */
export function mlInjectionScore(text: string): number;
/**
 * Hot-swap the HashLR model from a signed cloud bundle if a newer version is published - retrain and push
 * centrally without redeploying the SDK. Returns the new version if updated, else null. Fail-safe: any
 * error (network, bad signature, older/mismatched version) keeps the current embedded model. URL defaults
 * to env NEMESIS_MODEL_URL. When NEMESIS_MODEL_URL is set, SentinelClient also auto-refreshes periodically.
 */
export function refreshModel(url?: string, opts?: { timeoutMs?: number }): Promise<number | null>;
export const MODEL_VERSION: number;
export const ML_BLOCK_THRESHOLD: number;
export const ML_FLAG_THRESHOLD: number;

declare const _default: { sentinel: typeof sentinel; report: typeof report; reportLLM: typeof reportLLM; pathShape: typeof pathShape };
export default _default;
