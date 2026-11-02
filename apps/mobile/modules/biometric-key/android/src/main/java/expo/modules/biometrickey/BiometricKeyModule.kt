package expo.modules.biometrickey

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

// SEC-018 / SEC-019 / SEC-023 / SEC-067.
// EC secp256r1 key in the Android Keystore: user auth required per use (timeout 0) with BIOMETRIC_STRONG only, invalidated by
// biometric enrollment, StrongBox when available (else TEE), NO device-credential fallback. The signature comes from a
// BiometricPrompt CryptoObject, so the key is only usable after a successful strong biometric. Nothing returns a boolean "ok".

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val SIG_ALG = "SHA256withECDSA"

private class BK(code: String, msg: String) : CodedException(code, msg, null)

private fun b64urlDecode(s: String): ByteArray = Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
private fun b64urlEncode(b: ByteArray): String = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

class BiometricKeyModule : Module() {
  private val context: Context
    get() = appContext.reactContext ?: throw BK("UNKNOWN", "no context")

  private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

  private fun buildSpec(alias: String, strongBox: Boolean): KeyGenParameterSpec {
    val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      .setInvalidatedByBiometricEnrollment(true)
    if (strongBox) b.setIsStrongBoxBacked(true)
    return b.build()
  }

  override fun definition() = ModuleDefinition {
    Name("BiometricKey")

    AsyncFunction("isDeviceSecure") {
      (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
    }

    AsyncFunction("isSupported") {
      val bm = BiometricManager.from(context)
      val reason = when (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> "ok"
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "NOT_ENROLLED"
        else -> "HARDWARE_UNAVAILABLE"
      }
      mapOf(
        "secureHardware" to true, // verified for real at generateKey() via KeyInfo
        "biometricEnrolled" to (reason == "ok"),
        "reason" to reason
      )
    }

    AsyncFunction("hasKey") { alias: String -> keyStore().containsAlias(alias) }

    AsyncFunction("generateKey") { alias: String, _allowSoftware: Boolean ->
      // Software keys are never allowed on Android (no dev exception): the emulator Keystore is still a Keystore, and
      // isInsideSecureHardware is checked below.
      val ks = keyStore()
      if (ks.containsAlias(alias)) ks.deleteEntry(alias)
      val wantStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
      val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
      try {
        kpg.initialize(buildSpec(alias, wantStrongBox))
      } catch (e: Exception) {
        throw BK("HARDWARE_UNAVAILABLE", "keygen init failed")
      }
      var usedStrongBox = wantStrongBox
      val pair = try {
        kpg.generateKeyPair()
      } catch (e: StrongBoxUnavailableException) {
        // StrongBox preferred but optional (user decision): retry on the TEE.
        usedStrongBox = false
        kpg.initialize(buildSpec(alias, false))
        kpg.generateKeyPair()
      } catch (e: Exception) {
        throw BK("HARDWARE_UNAVAILABLE", "keygen failed")
      }
      val priv = pair.private
      val info = KeyFactory.getInstance(priv.algorithm, ANDROID_KEYSTORE).getKeySpec(priv, KeyInfo::class.java)
      if (!info.isInsideSecureHardware) {
        ks.deleteEntry(alias)
        throw BK("HARDWARE_UNAVAILABLE", "key not in secure hardware")
      }
      val level = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) "strongbox" else "tee"
      } else if (usedStrongBox) "strongbox" else "tee"
      mapOf("publicKeySpki" to b64urlEncode(pair.public.encoded), "securityLevel" to level)
    }

    AsyncFunction("sign") { alias: String, messageB64Url: String, promptTitle: String, promise: Promise ->
      val activity = appContext.currentActivity as? FragmentActivity
        ?: throw BK("UNKNOWN", "no activity")
      val message = try { b64urlDecode(messageB64Url) } catch (e: Exception) { throw BK("UNKNOWN", "bad message") }
      val signature = Signature.getInstance(SIG_ALG)
      try {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: throw BK("KEY_INVALIDATED", "missing key")
        signature.initSign(key)
      } catch (e: KeyPermanentlyInvalidatedException) {
        throw BK("KEY_INVALIDATED", "key invalidated")
      } catch (e: CodedException) {
        throw e
      } catch (e: Exception) {
        // UnrecoverableKeyException etc: treat an unusable key like an invalidated one.
        throw BK("KEY_INVALIDATED", "key unusable")
      }
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(promptTitle)
        .setNegativeButtonText("Use PIN")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setConfirmationRequired(false)
        .build()
      activity.runOnUiThread {
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            try {
              val s = result.cryptoObject?.signature ?: throw BK("UNKNOWN", "no crypto object")
              s.update(message)
              promise.resolve(mapOf("signature" to b64urlEncode(s.sign())))
            } catch (e: CodedException) {
              promise.reject(e)
            } catch (e: Exception) {
              promise.reject(BK("UNKNOWN", "sign failed"))
            }
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            val code = when (errorCode) {
              BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> "USER_CANCELED"
              BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "LOCKOUT"
              BiometricPrompt.ERROR_NO_BIOMETRICS -> "NOT_ENROLLED"
              BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE -> "HARDWARE_UNAVAILABLE"
              else -> "UNKNOWN"
            }
            promise.reject(BK(code, "prompt error"))
          }
          // onAuthenticationFailed: a non-matching attempt; the prompt stays open until success, cancel or lockout.
        })
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
      }
    }

    AsyncFunction("deleteKey") { alias: String ->
      val ks = keyStore()
      if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }
  }
}
