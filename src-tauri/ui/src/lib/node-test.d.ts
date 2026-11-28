// Minimal types for the Node built-ins the `*.test.ts` files and `vite.config.ts` use. There is no
// `@types/node` here.

declare module "node:test" {
  type TestFn = () => void | Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): Promise<void>;
  export default test;
}

declare module "node:assert/strict" {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
    match(value: string, pattern: RegExp, message?: string): void;
  };
  export default assert;
}

declare module "node:fs" {
  export function readFileSync(path: URL, encoding: "utf8"): string;
}
