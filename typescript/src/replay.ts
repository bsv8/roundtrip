import { RoundtripError } from './errors.js'

/** A request id the receiver has already claimed, and how long the claim lives. */
export interface ReplayClaim {
  /** base64url digest of the signed request bytes. */
  id: string
  /** Unix seconds; the claim is kept until this moment, inclusive. */
  retainUntil: number
}

/**
 * The only state interface the core needs.
 *
 * `claim` must be atomic across every instance that can receive the same
 * request: a losing caller must observe `false` and must not run the business
 * handler. `complete` records that the claimed work finished. There is no
 * release, on purpose: a cancelled or failed execution must not hand the same
 * request id back to a second execution.
 */
export interface ReplayGuard {
  readonly capabilities: ReplayCapabilities
  claim (claim: ReplayClaim): Promise<boolean>
  complete (id: string): Promise<void>
}

export interface ReplayCapabilities {
  /** Survives a process restart. */
  readonly persistent: boolean
  /** Shared between instances. */
  readonly shared: boolean
  /** Replays a completed request to recover its business result. */
  readonly resultCache: boolean
}

interface Entry {
  retainUntil: number
  completed: boolean
}

/**
 * Single process, in memory implementation.
 *
 * It is enough for demos, tests and business flows without persistent side
 * effects. It is not enough for a restart or a second instance: nothing is
 * written to disk and nothing is shared, so after either event a replayed
 * request is accepted again. A production deployment has to supply a
 * persistent, shared store, and has to make the side effect idempotent with its
 * own transaction.
 */
export class MemoryReplayGuard implements ReplayGuard {
  readonly capabilities: ReplayCapabilities = { persistent: false, shared: false, resultCache: false }
  readonly #entries = new Map<string, Entry>()
  readonly #nowSeconds: () => number

  /**
   * `nowSeconds` must be the same clock the core uses. Retention is a security
   * decision: if the sweep ran on a different clock than the expiry check, a
   * record could be dropped while the request is still inside its window, or
   * kept long after it is not.
   */
  constructor (nowSeconds: () => number = (): number => Math.floor(Date.now() / 1000)) {
    this.#nowSeconds = nowSeconds
  }

  async claim (claim: ReplayClaim): Promise<boolean> {
    if (typeof claim.id !== 'string' || claim.id.length === 0) {
      throw new RoundtripError('ERR_REPLAYED', 'replay claim needs a request id')
    }
    this.#sweep()
    if (this.#entries.has(claim.id)) return false
    this.#entries.set(claim.id, { retainUntil: claim.retainUntil, completed: false })
    return true
  }

  async complete (id: string): Promise<void> {
    const entry = this.#entries.get(id)
    if (entry != null) entry.completed = true
  }

  /** Drops records that can no longer pass the expiry check of any receiver. */
  #sweep (): void {
    const now = this.#nowSeconds()
    for (const [id, entry] of this.#entries) {
      if (entry.retainUntil < now) this.#entries.delete(id)
    }
  }

  /** Test and diagnostic surface; the production core never reads it. */
  get size (): number {
    this.#sweep()
    return this.#entries.size
  }

  stateOf (id: string): 'absent' | 'claimed' | 'completed' {
    this.#sweep()
    const entry = this.#entries.get(id)
    if (entry == null) return 'absent'
    return entry.completed ? 'completed' : 'claimed'
  }

  clear (): void {
    this.#entries.clear()
  }
}
