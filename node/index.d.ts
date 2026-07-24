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
export function sentinel(config: SentinelConfig): (req: any, res: any, next: (err?: unknown) => void) => void;
export function report(token: string, events: RequestEvent[], opts?: { endpoint?: string }): Promise<void>;
export function reportLLM(token: string, exchange: LLMExchange, opts?: { endpoint?: string }): Promise<void>;
export function pathShape(path: string): string;
declare const _default: { sentinel: typeof sentinel; report: typeof report; reportLLM: typeof reportLLM; pathShape: typeof pathShape };
export default _default;
