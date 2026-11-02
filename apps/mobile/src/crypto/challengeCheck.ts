// M-01: the client must never sign a challenge whose fields differ from what it expects. Pure TS.
// All checks fail closed (return false); callers refuse to prompt for biometrics on false.
interface Fields {
  purpose: string;
  deviceId: string;
  boundHash?: string | undefined;
}

export const isValidLoginChallenge = (c: Fields, ownDeviceId: string): boolean =>
  c.purpose === 'login' && c.deviceId === ownDeviceId && !c.boundHash;

export const isValidEnrollChallenge = (c: Fields, ownDeviceId: string): boolean =>
  c.purpose === 'enroll' && c.deviceId === ownDeviceId && !c.boundHash;

/** `expectedBoundHash` is computed locally from the frozen transaction (or action). */
export const isValidStepUpChallenge = (c: Fields, ownDeviceId: string, expectedBoundHash: string): boolean =>
  c.purpose === 'stepup' && c.deviceId === ownDeviceId && !!c.boundHash && c.boundHash === expectedBoundHash;
