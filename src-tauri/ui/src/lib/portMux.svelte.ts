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
  /** Wraps the port fields. Focus moving between them does not count as leaving. */
  group = $state<HTMLElement | undefined>();

  #ports: () => PortPair;
  /** The SOCKS port to restore when multiplexing is turned off. */
  #separateSocks = 0;

  constructor(ports: () => PortPair) {
    this.#ports = ports;
    // Values changed from elsewhere (another session, a reverted draft) are evaluated at once;
    // values being typed wait for focus to leave the group.
    $effect(() => {
      const pair = this.#ports();
      const typing = !!this.group && this.group.contains(document.activeElement);
      if (!typing) untrack(() => (this.on = sharesPort(pair)));
    });
  }

  /** Attach to the group's `focusout`. */
  onFocusOut = (event: FocusEvent) => {
    const next = event.relatedTarget;
    if (next instanceof Node && this.group?.contains(next)) return;
    this.on = sharesPort(this.#ports());
  };

  /** The checkbox: returns the ports to apply, or null when there is nothing to share. */
  toggle(on: boolean): PortPair | null {
    const pair = this.#ports();
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
