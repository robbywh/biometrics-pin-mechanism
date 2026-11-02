# Device security checklist (T11, T21). NOT yet executed on hardware: tick with device, OS, date, tester.

- [ ] Android: screenshot / screen recording of any screen is black (FLAG_SECURE via usePreventScreenCapture).
- [ ] iOS: screen recording shows blocked content; app switcher shows the CryptoApp cover (inactive + background).
- [ ] Android: app switcher shows the cover (not balances).
- [ ] Background 29 s -> still unlocked; background 31 s -> lock screen; token absent (next API call needs unlock).
- [ ] 5 min foreground inactivity -> lock screen. Cold start -> lock screen.
- [ ] Device without a passcode -> blocking "Set a device passcode" screen.
- [ ] Clipboard never contains the PIN; no third-party keyboard appears for PIN entry (custom keypad).
- [ ] Android backup extraction (`adb backup`/ device transfer) contains no tokens; iOS keychain items are ThisDeviceOnly.
- [ ] Release build refuses an http:// API URL at startup; proxy without trusted CA cannot read traffic (TLS; pinning not required in demo).
- [ ] biometric-key checklist in `modules/biometric-key/TESTING.md` executed on one iOS and one Android device.
