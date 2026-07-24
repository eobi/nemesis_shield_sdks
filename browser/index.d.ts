export interface InitOptions {
  token: string;
  endpoint?: string;
  selfOrigin?: string;
  /** Redirect out of an un-approved frame ancestor (clickjacking). Default false. */
  frameBust?: boolean;
  env?: unknown;
  fetch?: typeof fetch;
}

export interface ShapeResult {
  route: string;
  method: string;
  shape: string;
}

/** Client-side event channels. connect = fetch/XHR/beacon/image/WebSocket/EventSource. */
export type EventKind =
  | "connect"
  | "script"
  | "inline"
  | "form"
  | "payform"
  | "field"
  | "frame";

export interface Shield {
  install(): Shield;
  refresh(): void;
  flush(): void;
  decide(shape: string): string | null;
  shapeOf(kind: string, origin: string): ShapeResult;
  shouldBlock(kind: EventKind, origin: string): boolean;
  isPaymentField(el: unknown): boolean;
  isPaymentForm(form: unknown): boolean;
}

declare const NemesisShield: {
  createShield(opts: InitOptions): Shield;
  init(opts: InitOptions): Shield;
  shapeOf(kind: string, origin: string): ShapeResult;
  fnv1a(s: string): string;
};

export default NemesisShield;
