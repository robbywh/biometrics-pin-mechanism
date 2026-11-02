import { AutoLock, INACTIVITY_MS } from './autoLock';

function make(delaySec = 30, unlocked = true) {
  let now = 1_000_000;
  const timers: { id: number; at: number; fn: () => void }[] = [];
  let id = 0;
  const lock = jest.fn();
  const al = new AutoLock({
    now: () => now,
    setTimer: (fn, ms) => { const t = { id: ++id, at: now + ms, fn }; timers.push(t); return t.id; },
    clearTimer: (h) => { const i = timers.findIndex((t) => t.id === h); if (i >= 0) timers.splice(i, 1); },
    getDelaySec: () => delaySec,
    isUnlocked: () => unlocked,
    lock,
  });
  const advance = (ms: number) => { now += ms; for (const t of [...timers]) if (t.at <= now) { timers.splice(timers.indexOf(t), 1); t.fn(); } };
  return { al, lock, advance, setUnlocked: (v: boolean) => { unlocked = v; } };
}

describe('auto-lock (SEC-050, test 19)', () => {
  it('background longer than 30 s locks; 30 s or less on return does not (timer-less return path)', () => {
    const a = make();
    a.al.onAppState('background');
    a.advance(29_000);
    a.al.onAppState('active');
    expect(a.lock).not.toHaveBeenCalled();
    a.al.onAppState('background');
    a.advance(31_000); // timer fires while in background
    expect(a.lock).toHaveBeenCalledTimes(1);
  });
  it('timers suspended in background: wall clock on return still locks', () => {
    let now = 0;
    const lock = jest.fn();
    const al = new AutoLock({ now: () => now, setTimer: () => 0, clearTimer: () => undefined, getDelaySec: () => 30, isUnlocked: () => true, lock });
    al.onAppState('background');
    now += 31_000; // OS suspended our timers; only the clock moved
    al.onAppState('active');
    expect(lock).toHaveBeenCalledTimes(1);
    al.onAppState('background');
    now += 5_000;
    al.onAppState('active');
    expect(lock).toHaveBeenCalledTimes(1);
  });
  it('immediate option locks on background', () => {
    const a = make(0);
    a.al.onAppState('background');
    expect(a.lock).toHaveBeenCalledTimes(1);
  });
  it('inactive alone never starts the background timer', () => {
    const a = make();
    a.al.onAppState('inactive');
    a.advance(120_000);
    expect(a.lock).not.toHaveBeenCalled();
  });
  it('5 minutes of foreground inactivity locks; a touch resets the timer', () => {
    const a = make();
    a.al.touch();
    a.advance(INACTIVITY_MS - 1000);
    a.al.touch();
    a.advance(INACTIVITY_MS - 1000);
    expect(a.lock).not.toHaveBeenCalled();
    a.advance(2000);
    expect(a.lock).toHaveBeenCalledTimes(1);
  });
  it('does nothing when already locked', () => {
    const a = make(30, false);
    a.al.touch();
    a.al.onAppState('background');
    a.advance(600_000);
    expect(a.lock).not.toHaveBeenCalled();
  });
});
