// In-memory fakes for expo-secure-store and AsyncStorage, with spies so tests can prove what was written where.
export const secure = new Map<string, string>();
export const plain = new Map<string, string>();
export const secureOptions: Record<string, unknown>[] = [];
export const failSecureWrites = { value: false };

export const secureStoreFake = {
  WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: 'WHEN_PASSCODE_SET_THIS_DEVICE_ONLY',
  setItemAsync: async (k: string, v: string, o?: Record<string, unknown>) => {
    if (failSecureWrites.value) throw new Error('keychain write failed');
    secureOptions.push({ key: k, ...(o ?? {}) });
    secure.set(k, v);
  },
  getItemAsync: async (k: string) => secure.get(k) ?? null,
  deleteItemAsync: async (k: string) => { secure.delete(k); },
};
export const asyncStorageFake = {
  setItem: async (k: string, v: string) => { plain.set(k, v); },
  getItem: async (k: string) => plain.get(k) ?? null,
  removeItem: async (k: string) => { plain.delete(k); },
  clear: async () => { plain.clear(); },
};
export function resetFakes() {
  secure.clear(); plain.clear(); secureOptions.length = 0; failSecureWrites.value = false;
}
