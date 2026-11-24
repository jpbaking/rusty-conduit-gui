// One shared check of the configured `ssh` program, so the Connection tab (where the engine is
// chosen) and the Advanced tab (where the program is set) show the same result.

import { api, errorMessage } from "./api";
import { checkStatus } from "./format";
import type { OpenSshBinaryInfo } from "./types";

/** Why OpenSSH was turned down: the program checked and what the check found. */
export interface Fallback {
  bin: string;
  info: OpenSshBinaryInfo | null;
  error: string | null;
}

class OpensshCheck {
  /** The program the current result or check is for; `""` means the default `ssh`. */
  bin = $state<string | null>(null);
  checking = $state(false);
  info = $state.raw<OpenSshBinaryInfo | null>(null);
  error = $state<string | null>(null);
  #run = 0;

  readonly status = $derived(this.info ? checkStatus(this.info) : null);

  /** Whether the result (or the check running) describes exactly `bin`. */
  covers(bin: string): boolean {
    return this.bin === bin && (this.checking || this.info !== null || this.error !== null);
  }

  /** Checks `bin` now. A result only ever describes the exact program it was read from. */
  async run(bin: string): Promise<void> {
    const run = ++this.#run;
    this.bin = bin;
    this.checking = true;
    this.info = null;
    this.error = null;
    try {
      const info = await api.checkOpensshBinary(bin || undefined);
      if (run === this.#run) this.info = info;
    } catch (error) {
      if (run === this.#run) this.error = errorMessage(error);
    } finally {
      if (run === this.#run) this.checking = false;
    }
  }

  /** Checks `bin` unless the current result already describes it. */
  ensure(bin: string): void {
    if (!this.covers(bin)) void this.run(bin);
  }
}

export const opensshCheck = new OpensshCheck();
