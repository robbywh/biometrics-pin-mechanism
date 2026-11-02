// SEC-050: auto-lock. Background > delay (default 30 s; 0 / 30 / 60 s) or 5 min foreground inactivity => lock().
// Timers can be suspended in the background, so on return we also compare wall-clock timestamps.
export const INACTIVITY_MS = 5 * 60 * 1000;

export interface AutoLockDeps {
  now: () => number;
  setTimer: (fn: () => void, ms: number) => unknown;
  clearTimer: (h: unknown) => void;
  getDelaySec: () => number;
  isUnlocked: () => boolean;
  lock: () => void;
}

export class AutoLock {
  private bgAt: number | null = null;
  private bgTimer: unknown = null;
  private idleTimer: unknown = null;

  constructor(private readonly d: AutoLockDeps) {}

  /** AppState: 'active' | 'inactive' | 'background'. 'inactive' alone never starts the timer (the privacy overlay covers it). */
  onAppState(state: string): void {
    if (state === 'background') {
      this.clearIdle();
      if (this.bgAt === null) {
        this.bgAt = this.d.now();
        const delayMs = this.d.getDelaySec() * 1000;
        if (delayMs === 0) this.fire();
        else this.bgTimer = this.d.setTimer(() => this.fire(), delayMs);
      }
    } else if (state === 'active') {
      if (this.bgAt !== null) {
        const away = this.d.now() - this.bgAt;
        this.clearBg();
        if (away >= this.d.getDelaySec() * 1000) this.fire();
      }
      this.touch();
    }
  }

  /** Call on every user touch while foreground. */
  touch(): void {
    this.clearIdle();
    if (!this.d.isUnlocked()) return;
    this.idleTimer = this.d.setTimer(() => this.fire(), INACTIVITY_MS);
  }

  dispose(): void {
    this.clearBg();
    this.clearIdle();
  }

  private fire(): void {
    this.clearBg();
    this.clearIdle();
    if (this.d.isUnlocked()) this.d.lock();
  }
  private clearBg() {
    if (this.bgTimer !== null) this.d.clearTimer(this.bgTimer);
    this.bgTimer = null;
    this.bgAt = null;
  }
  private clearIdle() {
    if (this.idleTimer !== null) this.d.clearTimer(this.idleTimer);
    this.idleTimer = null;
  }
}
