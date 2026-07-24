export interface InitOptions {
  token: string;
  endpoint?: string;
  selfOrigin?: string;
  env?: unknown;
  fetch?: typeof fetch;
}

export interface ShapeResult {
  route: string;
  method: string;
  shape: string;
}

export interface Shield {
  install(): Shield;
  refresh(): void;
  flush(): void;
  decide(shape: string): string | null;
  shapeOf(kind: string, origin: string): ShapeResult;
  shouldBlock(kind: "script" | "connect" | "form", origin: string): boolean;
}

declare const NemesisShield: {
  createShield(opts: InitOptions): Shield;
  init(opts: InitOptions): Shield;
  shapeOf(kind: string, origin: string): ShapeResult;
  fnv1a(s: string): string;
};

export default NemesisShield;
