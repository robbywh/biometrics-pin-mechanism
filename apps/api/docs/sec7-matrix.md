# security-spec section 7: backend tests 1-14 -> test functions

All tests live in `apps/api/internal/e2e` unless noted; every HTTP response in them is validated against the canonical `openapi.yaml`
(`validatingTransport` in `harness_test.go`). Run: `make -C apps/api test`.

| # | Requirement | Test function(s) |
|---|---|---|
| 1 | 50 parallel wrong PINs: <= 5 evaluated, then 423; durable across restart | `TestSec7_01_ParallelGuessesAtMostFiveEvaluated`; store level: `store.TestReserveAttemptConcurrent50`, `store.TestRestartKeepsState`; `TestSec66_RestartKeepsSecurityState` |
| 2 | Correct PIN during lock => 423, unchanged; after expiry works and resets | `TestSec7_02_LockScheduleAndCorrectPinDuringLock`, `TestSec7_02_CorrectPinAfterExpiryResets`, `TestLockout_NinthFailureThenCorrectPin` |
| 3 | pin/verify without device credential => 401, counter unchanged | `TestSec7_03_PinVerifyNeedsDeviceCredential` |
| 4 | POST /pin never overwrites; demo-login without secret => 401; bootstrap token on /dashboard => 403 | `TestSec7_04_SetPinNeverOverwrites`, `TestSec7_04_DemoLoginRequiresSecretAndIsUniform`, `TestSec7_04_BootstrapTokenScopeAndTTL` |
| 5 | Hard lock blocks PIN and biometric; reset revokes all, sets cooling-off | `TestSec7_05_HardLockBlocksPinAndBiometric_ResetRecovers` |
| 6 | Replay, concurrent verify, expired nonce, purpose confusion, byte-identical failure modes | `TestSec7_06_ReplayConcurrentExpiredPurposeConfusion`, `TestSec7_06_LoginSignatureFailsAsStepUp`, `TestSec7_06_FailureModesAreByteIdentical`, `TestSec7_06_DecoyChallengeShape`, `TestSec30_*` |
| 7 | Enroll needs PIN step-up, PoP, P-256 only, second enroll replaces first | `TestSec7_07_EnrollmentRequirements`, `TestSec7_07_InvalidPublicKeys422`, `TestSec7_07_SecondEnrollReplacesFirst`, `TestSec22_*`, `TestSec23_*`; `cryptomsg.TestParseSPKIRejects` |
| 8 | Refresh reuse revokes family; UNLOCK_REQUIRED; logout | `TestSec7_08_RefreshReuseRevokesFamily`, `TestSec7_08_ConcurrentRefreshOneWinner`, `TestSec7_08_UnlockWindowAndIdle`, `TestSec7_08_IdleWindow`, `TestSec32_AbsoluteAndIdleLifetime`, `TestSec36_LogoutInvalidatesEverything`, `TestSec37_*`, `TestSec31_AccessTokenClaims`, `TestForgedAccessTokensRejected`, `TestSec45_PinChangeRevokesOtherDevices` |
| 9 | Tx tamper, token reuse, other session, threshold, cooling-off, double-submit | `TestSec7_09_TamperedFieldsRejectedAndTokenBurned`, `TestSec7_09_TokenReuseOtherSessionOtherUser`, `TestSec7_09_ConcurrentDoubleSubmitCreatesOneTransaction`, `TestSec7_09_ConcurrentDistinctKeysOneTokenOneTx`, `TestSec41_BioOnlyThresholdAndCoolingOff`, `TestSec47_CoolingOffClockAdvance`, `TestSec42_StepUpPinSharesLockout`, `TestTransaction_*` (incl. fault injection) |
| 10 | IDOR => 404 | `TestSec7_10_IDOR`, `TestSec38_RevokeOtherDeviceNeedsPinStepUp`, `TestListDevicesOnlyOwnWithCurrentFlag` |
| 11 | Canary secrets never logged; no pin/hash/salt response keys; error fuzz | `TestSec7_11_CanarySecretsNeverLogged`, `TestSec7_11_NoSecretPropertiesInResponses`, `TestErrorFuzz_NoInternalsLeak`, `TestHeadersAndPanicRecovery`; `platform/log.TestAllowlistAndRedaction`; `server.FuzzValidate` |
| 12 | PIN policy table; Argon2 + wrong pepper | `pin.TestPolicy`, `pin.TestWrongPepperFails`, `pin.TestPepperVersionAndParamUpgrade`, `TestSec7_12_WeakPinsRejectedByServer`, `TestSec3_PepperUpgradeOnLogin` |
| 13 | Rate limits per endpoint; 200 concurrent verifies bounded | `TestSec7_13_DemoLoginLimits`, `TestSec7_13_PinVerifyDeviceAndIPLimits`, `TestSec7_13_BiometricLimits`, `TestSec7_13_RefreshStepUpEnrollPinTxLimits`, `TestSec9_RotatingIPsHitUserLock`, `TestSec5b_HashingSaturationReturns429WithoutCountingAttempt`, `TestSec7_13_ConcurrentVerifiesBounded`; `pin.TestSemaphoreBoundsConcurrencyAndReturnsBusy`; `config.TestDefaultLimitsMatchSEC057` |
| 14 | Startup fails with missing pepper / DEMO_MODE in prod | `config.TestFailClosed`, `cmd/api.TestStartupFailsClosed`, `config.TestConfigDumpRedaction`, `TestHealthzFailsClosedWhenStoreUnavailable` |

Not automatable here: statistical/timing equalisation of SEC-029 (best effort, not measured), real Apple/Google attestation (not implemented, SEC-022 demo scope).
