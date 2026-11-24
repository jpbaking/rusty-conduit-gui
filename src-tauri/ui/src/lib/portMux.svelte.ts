// Single-port multiplex state for a pair of HTTP/SOCKS port fields.
//
// Whether the pair is shared is decided when focus leaves the port fields, not on each
// keystroke: typing 33301 into SOCKS passes through 3330, which must not collapse the fields
// just because HTTP is 3330.

import { untrack } from "svelte";
import { isPort } from "./validate";

export interface PortPair {
  http: number;
  socks: number;
}

/** Both listeners on one port. `Object.is`, so a cleared shared field (NaN in both) still counts. */
export function sharesPort({ http, socks }: PortPair): boolean {
  return Object.is(http, socks) && http !== 0;
}

/** The port to share when multiplexing is turned on, or null if neither is usable. */
export function shareablePort({ http, socks }: PortPair): number | null {
  return [http, socks].find((port) => port !== 0 && isPort(port)) ?? null;
}

export class PortMux {
  /** Whether the pair is shown as one shared field. */
  on = $state(false);
  /** Turned on by itself, not by the checkbox, so the UI explains why the fields merged. */
  autoOn = $state(false);
  /** Wraps the port fields. Focus moving between them does not count as leaving. */
  group = $state<HTMLElement | undefined>();

  #ports: () => PortPair;
  /** The SOCKS port to restore when multiplexing is turned off. */
  #separateSocks = 0;
  /** The next outside change of the ports is the app's own, so a merge it causes is explained. */
  #announceNext = false;
  /** The pair last evaluated, so edits elsewhere in the draft leave the state alone. */
  #last: PortPair | null = null;

  constructor(ports: () => PortPair) {
    this.#ports = ports;
    // Values changed from elsewhere (another session, a reverted draft) are evaluated at once;
    // values being typed wait for focus to leave the group.
    $effect(() => {
      const pair = this.#ports();
      const typing = !!this.group && this.group.contains(document.activeElement);
      if (typing) return;
      const last = this.#last;
      if (last && Object.is(last.http, pair.http) && Object.is(last.socks, pair.socks)) return;
      this.#last = { ...pair };
      untrack(() => {
        const shared = sharesPort(pair);
        // Another session or a reverted draft is not a surprise; a fill-in by the app is.
        this.autoOn = this.#announceNext && shared && !this.on;
        this.#announceNext = false;
        this.on = shared;
      });
    });
  }

  /** Attach to the group's `focusout`. */
  onFocusOut = (event: FocusEvent) => {
    const next = event.relatedTarget;
    if (next instanceof Node && this.group?.contains(next)) return;
    const pair = this.#ports();
    this.#last = { ...pair };
    const shared = sharesPort(pair);
    // Typing the same port into both fields merges them: flag it so the UI can say so.
    this.autoOn = shared && (this.autoOn || !this.on);
    this.on = shared;
  };

  /** Call right before the app itself sets the ports, such as filling in defaults. */
  announce(): void {
    this.#announceNext = true;
  }

  /** The checkbox: returns the ports to apply, or null when there is nothing to share. */
  toggle(on: boolean): PortPair | null {
    const pair = this.#ports();
    this.autoOn = false;
    if (on) {
      const port = shareablePort(pair);
      if (port === null) return null;
      this.#separateSocks = pair.socks;
      this.on = true;
      return { http: port, socks: port };
    }
    this.on = false;
    return { http: pair.http, socks: this.#separateSocks === pair.http ? 0 : this.#separateSocks };
  }
}
