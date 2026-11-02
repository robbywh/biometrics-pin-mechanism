import React, { useCallback, useEffect, useState } from 'react';
import { Banner, Button, Card, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { describeError } from '../../api/errors';
import type { Device } from '../../api/endpoints';
import { loadDevices, revokeCurrentDevice, revokeOtherDevice } from '../../flows/account';
import { flowErrorText } from '../../ui/hooks';
import type { PinBuffer } from '../../pin/buffer';

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [target, setTarget] = useState<Device | null>(null); // revoke-other: PIN prompt
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resetKey, setResetKey] = useState(0);
  const load = useCallback(async () => {
    const r = await loadDevices();
    if (r.ok) setDevices(r.data.devices); else setError(describeError(r.error));
  }, []);
  useEffect(() => { void load(); }, [load]);

  const onPin = async (pin: PinBuffer) => {
    if (!target) { pin.clear(); return; }
    setBusy(true);
    const r = await revokeOtherDevice(target.id, pin);
    setBusy(false); setResetKey((k) => k + 1);
    if (r.ok) { setTarget(null); setError(null); void load(); } else setError(flowErrorText(r.error));
  };

  if (target) {
    return (
      <Screen scroll>
        <T kind="h2">Remove {target.name}</T>
        {error ? <Banner tone="error" text={error} /> : null}
        <PinPad label="Confirm your PIN" onComplete={onPin} disabled={busy} resetKey={resetKey} />
        <Button title="Cancel" kind="secondary" onPress={() => { setTarget(null); setError(null); }} />
      </Screen>
    );
  }
  return (
    <Screen scroll>
      {error ? <Banner tone="error" text={error} /> : null}
      {devices.map((d) => (
        <Card key={d.id}>
          <T kind="h2">{d.name}{d.current ? ' (this device)' : ''}</T>
          <T kind="dim">{d.platform} - biometrics {d.biometricEnabled ? 'on' : 'off'}</T>
          {d.current
            ? <Button title="Remove this device" kind="danger" onPress={() => void revokeCurrentDevice().then((r) => { if (!r.ok) setError(flowErrorText(r.error)); })} />
            : <Button title="Remove" kind="secondary" onPress={() => { setError(null); setTarget(d); }} />}
        </Card>
      ))}
    </Screen>
  );
}
