// T20 / SEC-056: ADVISORY risk signals. Only src/api/* may import this (lint rule). Never used as a gate; no UI branches on it.
import * as Device from 'expo-device';

export interface RiskSignals {
  rooted?: boolean;
  debugger?: boolean;
  emulator?: boolean;
}

let cached: Promise<RiskSignals> | undefined;

export function getRiskSignals(): Promise<RiskSignals> {
  cached ??= (async () => {
    const out: RiskSignals = {};
    try {
      out.rooted = await Device.isRootedExperimentalAsync();
    } catch {
      /* unknown: omit */
    }
    if (typeof Device.isDevice === 'boolean') out.emulator = !Device.isDevice;
    if (__DEV__) out.debugger = true;
    return out;
  })();
  return cached;
}

export function __resetRiskForTests(): void {
  cached = undefined;
}
