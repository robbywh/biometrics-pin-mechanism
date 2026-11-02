import React from 'react';
import { Button, Screen, T } from '../ui/components';
import { boot } from '../auth/boot';

// SEC-034: fail closed when the device has no passcode / secure lock screen.
export default function NeedsPasscode() {
  return (
    <Screen>
      <T kind="title">Set a device passcode</T>
      <T>This app stores your credentials in the device secure storage, which requires a screen lock. Set a device passcode or biometrics in system settings, then come back.</T>
      <Button title="I have set a passcode" onPress={() => void boot()} />
    </Screen>
  );
}
