import React, { useRef, useState } from 'react';
import { TextInput } from 'react-native';
import { useRouter } from 'expo-router';
import { randomUUID } from 'expo-crypto';
import { Banner, Button, Card, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { color, radius } from '../../ui/theme';
import { flowErrorText, useCountdown } from '../../ui/hooks';
import { SendTransaction } from '../../flows/send';
import type { TransactionFields } from '../../api/endpoints';
import type { PinBuffer } from '../../pin/buffer';

const input = { color: color.text, backgroundColor: color.surface, borderRadius: radius.md, padding: 16, fontSize: 16, minHeight: 56 } as const;
type Stage = 'form' | 'confirm' | 'pin' | 'done';
const DEC = /^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$/;

export default function Send() {
  const router = useRouter();
  const flow = useRef<SendTransaction | null>(null);
  const [stage, setStage] = useState<Stage>('form');
  const [asset, setAsset] = useState<'BTC' | 'ETH' | 'USDC'>('ETH');
  const [destination, setDestination] = useState('');
  const [amount, setAmount] = useState('');
  const [fee, setFee] = useState('0.001');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const cd = useCountdown();

  const valid = /^[A-Za-z0-9]{26,90}$/.test(destination) && DEC.test(amount) && Number(amount) > 0 && DEC.test(fee);
  const fail = (e: { code: string; retryAfter?: number }) => {
    setError(flowErrorText(e));
    if ((e.code === 'PIN_LOCKED' || e.code === 'RATE_LIMITED' || e.code === 'COOLING_OFF') && e.retryAfter) cd.start(e.retryAfter);
  };

  // Issues the challenge; the fields are frozen inside SendTransaction from here on (changing anything starts a NEW flow).
  const begin = async () => {
    setBusy(true); setError(null);
    if (!flow.current) {
      const tx: TransactionFields = { asset, network: asset === 'BTC' ? 'bitcoin' : 'ethereum', destination, amount, fee, txNonce: randomUUID().toLowerCase(), expiry: Math.floor(Date.now() / 1000) + 300 };
      flow.current = new SendTransaction(tx);
    }
    const r = await flow.current.begin();
    setBusy(false);
    if (!r.ok) { flow.current = null; fail(r.error); return; }
    setStage('confirm');
  };

  const approve = async () => {
    const f = flow.current;
    if (!f) return;
    setBusy(true); setError(null);
    if (f.required !== 'pin') {
      const b = await f.proveWithBiometric();
      if (!b.ok) { setBusy(false); fail(b.error); if (b.restart) { await begin(); } return; }
      if (!b.data.fallbackToPin) { await submit(); return; }
    }
    setBusy(false);
    setStage('pin');
  };

  const onPin = async (pin: PinBuffer) => {
    const f = flow.current;
    if (!f) { pin.clear(); return; }
    setBusy(true);
    const r = await f.proveWithPin(pin);
    setResetKey((k) => k + 1);
    if (!r.ok) {
      fail(r.error);
      if (r.restart) { const again = await f.begin(); if (!again.ok) { flow.current = null; setStage('form'); fail(again.error); } }
      setBusy(false);
      return;
    }
    await submit();
  };

  const submit = async () => {
    const f = flow.current;
    if (!f) return;
    setBusy(true);
    const r = await f.submit();
    setBusy(false);
    if (r.ok) { setStage('done'); return; }
    fail(r.error);
    if (r.restart) { const again = await f.begin(); if (again.ok) setStage('confirm'); else { flow.current = null; setStage('form'); } }
  };

  if (stage === 'done') {
    return (
      <Screen>
        <T kind="title">Sent (demo)</T>
        <T kind="dim">The transaction was accepted by the mock backend.</T>
        <Button title="Done" onPress={() => router.back()} />
      </Screen>
    );
  }
  if (stage === 'pin') {
    return (
      <Screen scroll>
        {error ? <Banner tone="error" text={error} /> : null}
        {cd.left > 0 ? <T kind="warn">Try again in {cd.left}s</T> : null}
        <PinPad label="Enter your PIN to approve" onComplete={onPin} disabled={busy || cd.left > 0} resetKey={resetKey} />
      </Screen>
    );
  }
  if (stage === 'confirm' && flow.current) {
    const s = flow.current.summary;
    return (
      <Screen scroll>
        <T kind="title">Confirm</T>
        {error ? <Banner tone="error" text={error} /> : null}
        {/* Server-built summary: this is what the user approves (SEC-039), not locally formatted fields. */}
        <Card>
          <T kind="h2">{s?.title}</T>
          {s?.lines.map((l, i) => <T key={i}>{l}</T>)}
        </Card>
        <Card>
          <T kind="dim">You entered</T>
          <T>{flow.current.fields.amount} {flow.current.fields.asset} to {flow.current.fields.destination}</T>
          <T kind="dim">Fee {flow.current.fields.fee}</T>
        </Card>
        <Button title="Approve" onPress={() => void approve()} busy={busy} disabled={flow.current.divergence} testID="approve" />
        <Button title="Cancel" kind="secondary" onPress={() => { flow.current = null; setStage('form'); }} />
      </Screen>
    );
  }
  return (
    <Screen scroll>
      <T kind="title">Send</T>
      {error ? <Banner tone="error" text={error} /> : null}
      {cd.left > 0 ? <T kind="warn">Try again in {cd.left}s</T> : null}
      {(['BTC', 'ETH', 'USDC'] as const).map((a) => <Button key={a} title={a + (a === asset ? ' (selected)' : '')} kind={a === asset ? 'primary' : 'secondary'} onPress={() => setAsset(a)} />)}
      <TextInput accessibilityLabel="Destination address" style={input} value={destination} onChangeText={setDestination} autoCapitalize="none" autoCorrect={false} placeholder="destination address" placeholderTextColor={color.textDim} />
      <TextInput accessibilityLabel="Amount" style={input} value={amount} onChangeText={setAmount} keyboardType="decimal-pad" placeholder="amount" placeholderTextColor={color.textDim} />
      <TextInput accessibilityLabel="Network fee" style={input} value={fee} onChangeText={setFee} keyboardType="decimal-pad" placeholder="fee" placeholderTextColor={color.textDim} />
      <Button title="Review" onPress={() => void begin()} busy={busy} disabled={!valid || cd.left > 0} testID="review" />
    </Screen>
  );
}
