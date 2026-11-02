/** Keystore / Keychain alias of the biometric signing key for a device. */
export const biometricAlias = (deviceId: string): string => `bio.${deviceId}`;
