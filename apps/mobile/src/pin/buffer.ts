// SEC-053: PIN digits live ONLY in this mutable buffer (held in a React ref), never in state/context/stores/params/errors.
// The 6-digit string is materialised exactly once, inside `take()`, at the moment the request body is built; `take()` zeroes the
// buffer in the same call. JS strings are immutable so the string itself cannot be wiped (best effort, documented).
export const PIN_LENGTH = 6;

export class PinBuffer {
  private d = new Uint8Array(PIN_LENGTH);
  private n = 0;

  get length(): number {
    return this.n;
  }
  get full(): boolean {
    return this.n === PIN_LENGTH;
  }
  push(digit: number): boolean {
    if (!Number.isInteger(digit) || digit < 0 || digit > 9 || this.n >= PIN_LENGTH) return false;
    this.d[this.n++] = digit;
    return true;
  }
  pop(): void {
    if (this.n > 0) this.d[--this.n] = 0;
  }
  clear(): void {
    this.d.fill(0);
    this.n = 0;
  }
  /** Copy of the digits for local policy checks only. Caller must not retain it. */
  digits(): number[] {
    return Array.from(this.d.subarray(0, this.n));
  }
  equals(other: PinBuffer): boolean {
    if (this.n !== other.n) return false;
    let diff = 0;
    for (let i = 0; i < this.n; i++) diff |= this.d[i]! ^ other.d[i]!;
    return diff === 0;
  }
  /** Returns the PIN string and zeroes the buffer. Throws unless exactly 6 digits are present. */
  take(): string {
    if (this.n !== PIN_LENGTH) throw new Error('incomplete PIN');
    let s = '';
    for (let i = 0; i < PIN_LENGTH; i++) s += String(this.d[i]);
    this.clear();
    return s;
  }
}
