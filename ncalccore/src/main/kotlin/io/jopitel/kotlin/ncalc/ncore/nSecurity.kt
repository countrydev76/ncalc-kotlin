package io.jopitel.kotlin.ncalc.ncore

/**
 * /Users/magmajo/workdev/devcode/nhello/nkotlin/MagmaKotlin/MagmaTutorial/src/main/java/io/jopitel/java/tutorial/jca
 *
 * https://developer.android.com/preview/
 * https://github.com/ashishb/android-security-awesome/
 * https://github.com/patrickfav/armadillo
 * https://github.com/phxql/kotlin-crypto-example/blob/master/src/main/kotlin/de/mkammerer/Crypto.kt
 */

/**
 *
 */

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException
import com.sun.org.apache.xml.internal.security.utils.Base64

//import android.annotation.TargetApi
//import android.os.Build
//import android.security.keystore.KeyGenParameterSpec
//import android.security.keystore.KeyProperties
//import android.util.Base64
//import android.util.Log

import java.io.UnsupportedEncodingException
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
/**
 * nSecurity
 */
object nSecurity {
  const val TAG = "nSecurity"
  /**
   * Be sure to use a SecureRandom!
   */
  val mSecureRandom = SecureRandom()

  /**
   * Generates a key with [sizeInBits] bits.
   */
  fun generateKey(sizeInBits: Int): ByteArray {
    val result = ByteArray(sizeInBits/8)
    mSecureRandom.nextBytes(result)
    return result
  }

  /**
   * Generates an IV. The IV is always 128(16Byte) bit long.
   */
  fun generateIv(): ByteArray {
    val result = ByteArray(128/8)
    mSecureRandom.nextBytes(result)
    return result
  }
  /**
   * Generates a nonce for GCM mode. The nonce is always 96 bit long.
   */
  fun generateNonce(): ByteArray {
    val result = ByteArray(96/8)
    mSecureRandom.nextBytes(result)
    return result
  }
  /**
   * Hashing Utils
   * @author Sam Clarke <www.samclarke.com>
   * @license MIT
   *
   * https://www.samclarke.com/kotlin-hash-strings/
   */
  object Hash {
    fun sha512(input: String) = hashString("SHA-512", input)
    fun sha256(input: String) = hashString("SHA-256", input)
    fun sha1(input: String) = hashString("SHA-1", input)
    /**
     * Supported algorithms on Android:
     *
     * Algorithm	Supported API Levels
     * MD5          1+
     * SHA-1	      1+
     * SHA-224	    1-8,22+
     * SHA-256	    1+
     * SHA-384	    1+
     * SHA-512	    1+
     */
    private fun hashString(type: String, input: String): String {
      val HEX_CHARS = "0123456789ABCDEF"
      val bytes = MessageDigest
        .getInstance(type)
        .digest(input.toByteArray())
      val result = StringBuilder(bytes.size * 2)
      bytes.forEach {
        val i = it.toInt()
        result.append(HEX_CHARS[i shr 4 and 0x0f])
        result.append(HEX_CHARS[i and 0x0f])
      }
      return String(result)
    }
  }

  /**
   * https://github.com/phxql/kotlin-crypto-example/blob/master/src/main/kotlin/de/mkammerer/Crypto.kt
   * - "HmacSHA1" "HmacSHA256"
   */
  object Hmac {
    fun hmacSha1(input: String, key: String) =
      hmacString("HmacSHA1", input, key)
    fun hmacSha256(input: String, key: String) =
      hmacString("HmacSHA256", input, key)

    private fun hmacString(input: String, key: String, algorithm: String): String {
      val keySpec = SecretKeySpec(key.toByteArray(), algorithm)
      val mac = Mac.getInstance(algorithm)
      mac.init(keySpec)
      return String(mac.doFinal(input.toByteArray()))
    }
  }

  /**
   * RSA
   * https://www.masinamichele.it/2018/02/13/implementing-rsa-cryptography-in-kotlin/
   *
   * val kp = generateKeyPair()
   * encrypt(string, key)
   * decrypt(string)
   */
  object RSA {
    const val ALGORITHM = "RSA"
    const val AlgorithmRSAKeyBits = 2048
    const val AlgorithmRSATransform = "RSA/ECB/OAEPwithSHA-256andMGF1Padding"
    //Cipher.getInstance("RSA/ECB/OAEPwithMD5andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA-224andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA-384andMGF1Padding");
    //Cipher.getInstance("RSA/ECB/OAEPwithSHA-512andMGF1Padding");

    // Generates the key pair
    fun generateKeyPair(): KeyPair {
      val kp: KeyPair
      val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)

      kpg.initialize(AlgorithmRSAKeyBits)
      kp = kpg.genKeyPair()

      return kp
      //prefs.publicKey = kp.public.key()
      //prefs.privateKey = kp.private.key()
    }

    fun getKeyListWithKeyStore(): Enumeration<String> {
      /*
       * Load the Android KeyStore instance using the the
       * "AndroidKeyStore" provider to list out what entries are
       * currently stored.
       */
      val ks = KeyStore.getInstance("AndroidKeyStore")
      ks.load(null)
      val aliases = ks.aliases()
      return aliases
    }


    // Encrypts a string
    //fun encrypt(message: String, publicKey: String): String {
    //  return encrypt(message, publicKey.toPublicKey())
    //}

    fun encrypt(message: String, publicKey: PublicKey): String {
      val cipher: Cipher = Cipher.getInstance(AlgorithmRSATransform)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      val encryptedBytes = cipher.doFinal(message.toByteArray())
      return Base64.encode(encryptedBytes)
    }

    fun encrypt(message: String, privateKey: String): String {
      return encrypt(message, privateKey.toPrivateKey())
    }

    fun encrypt(message: String, privateKey: PrivateKey): String {
      val cipher: Cipher = Cipher.getInstance(AlgorithmRSATransform)
      cipher.init(Cipher.ENCRYPT_MODE, privateKey)
      val encryptedBytes = cipher.doFinal(message.toByteArray())
      return Base64.encode(encryptedBytes)
    }

    // Decrypts a message
    fun decrypt(message: String, publicKey: String): String {
      return decrypt(message, publicKey.toPublicKey())
    }
    fun decrypt(message: String, publicKey: PublicKey): String {
      val cipher: Cipher = Cipher.getInstance(AlgorithmRSATransform)
      cipher.init(Cipher.DECRYPT_MODE, publicKey)
      val decryptedBytes = cipher.doFinal(Base64.decode(message))
      return String(decryptedBytes)
    }
    fun decrypt(message: String, privateKey: PrivateKey): String {
      val cipher: Cipher = Cipher.getInstance(AlgorithmRSATransform)
      cipher.init(Cipher.DECRYPT_MODE, privateKey)
      val decryptedBytes = cipher.doFinal(Base64.decode(message))
      return String(decryptedBytes)
    }

    /**
     * Create signature by signing
     * @param message the signed JSON string (signed, not encrypted)
     * @param privateKey the base64-encoded private key to use for signing.
     * @return signature text
     *
     * https://www.pixelstech.net/article/1448118341-Signature-sign-verification-demo-in-Java
     */
    fun sign(message: String, privateKey: String): String {
      try {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey.toPrivateKey())
        sig.update(message.toByteArray())
        return sig.sign().toBase64()
      } catch (e: NoSuchAlgorithmException) {
        throw RuntimeException(e)
      } catch (e: InvalidKeyException) {
        throw RuntimeException(e)
      } catch (e: UnsupportedEncodingException) {
        throw RuntimeException(e)
      } catch (e: SignatureException) {
        throw RuntimeException(e)
      }
    }

    /**
     * Verifies that the data was signed with the given signature, and returns
     * the verified purchase. The data is in JSON format and signed
     * and product ID of the purchase.
     * @param message the signed JSON string (signed, not encrypted)
     * @param signature the signature for the data, signed with the private key
     * @param publicKey the base64-encoded public key to use for verifying.
     * @return result for verification
     *
     * https://www.pixelstech.net/article/1448118341-Signature-sign-verification-demo-in-Java
     */
    fun verify(message: String, signature: String, publicKey: String): Boolean {
      try {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initVerify(publicKey.toPublicKey())
        sig.update(message.toByteArray())
        if (!sig.verify(signature.toBase64Decode())) {
          throw InvalidSignatureException("It was awesome! Signature hasn't be invalid")
        }
      } catch (e: NoSuchAlgorithmException) {
        throw RuntimeException(e)
      } catch (e: InvalidKeyException) {
        throw RuntimeException(e)
      } catch (e: SignatureException) {
        throw RuntimeException(e)
      }
      return true
    }
    internal class InvalidSignatureException(message: String) : RuntimeException(message)
  }

  /**
   * AES
   *  https://stackoverflow.com/questions/49340005/encrypt-decrypt-string-kotlin
   *  https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
   */
  object AES {
    const val ALGORITHM = "AES"

    enum class Tranform(val localized: String) {
      AesCbcPKCS5Padding("AES/CBC/PKCS5Padding"),
      AesCbcPKCS7Padding("AES/CBC/PKCS7Padding"),
      AesGcmNoPadding("AES/GCM/NoPadding")
    }

    class Ciphertext(val ciphertext: ByteArray, val iv: ByteArray)

    fun encrypt(message: ByteArray, key: String, iv: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      val keySpec = SecretKeySpec(key.substring(0,16).toByteArray(),
        ALGORITHM
      )
      val ivSpec = IvParameterSpec(iv.substring(0,16).toByteArray())
      val cipher = Cipher.getInstance(transform.localized)
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
      val encryptedValue = cipher.doFinal(message)
      return Base64.encode(encryptedValue)
    }

    fun encrypt(message: String, key: String, iv: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return encrypt(message.toByteArray(), key, iv, transform)
    }

    fun decrypt(message: ByteArray, key: String, iv: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      val keySpec = SecretKeySpec(key.substring(0,16).toByteArray(),
        ALGORITHM
      )
      val ivSpec = IvParameterSpec(iv.substring(0,16).toByteArray())
      val cipher = Cipher.getInstance(transform.localized)
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
      val decryptedByteValue = cipher.doFinal(message)
      return String(decryptedByteValue)
    }

    fun decrypt(message: String, key: String, iv: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return decrypt(message.toByteArray(), key, iv, transform)
    }

    fun encrypt(message: String, key: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return encrypt(message, key, key, transform)
    }
    fun encrypt(message: ByteArray, key: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return encrypt(message, key, key, transform)
    }
    fun decrypt(message: String, key: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return decrypt(message, key, key, transform)
    }
    fun decrypt(message: ByteArray, key: String, transform: Tranform = Tranform.AesCbcPKCS5Padding): String {
      return decrypt(message, key, key, transform)
    }
    /**
     * Encrypts the given [plaintext] with the given [key] under AES CBC with PKCS5 padding.
     * This method generates a random IV.
     *
     * @return Ciphertext and IV
     *
     * https://github.com/phxql/kotlin-crypto-example/blob/master/src/main/kotlin/de/mkammerer/Crypto.kt
     */
    fun encryptCbc(plaintext: ByteArray, key: ByteArray): Ciphertext {
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val keySpec = SecretKeySpec(key, "AES")
      val iv = generateIv()
      val ivSpec = IvParameterSpec(iv)
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
      val ciphertext = cipher.doFinal(plaintext)
      return Ciphertext(ciphertext, iv)
    }

    /**
     * Encrypts the given [plaintext] with the given [key] under AES GCM.
     *
     * This method generates a random nonce.
     *
     * @return Ciphertext and nonce
     *
     * https://github.com/phxql/kotlin-crypto-example/blob/master/src/main/kotlin/de/mkammerer/Crypto.kt
     */
    fun encryptGcm(plaintext: ByteArray, key: ByteArray): Ciphertext {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val keySpec = SecretKeySpec(key, "AES")
      val nonce = generateNonce()
      val gcmSpec = GCMParameterSpec(128, nonce) // 128 bit authentication tag
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
      val ciphertext = cipher.doFinal(plaintext)
      return Ciphertext(ciphertext, nonce)
    }
  }

//  /**
//   * - Generates the key pair with keystore(23+ TEE or SE)
//   *   https://developer.android.com/training/articles/keystore?hl=ko#SecurityFeatures
//   *   https://developer.android.com/guide/topics/security/cryptography?hl=ko
//   */
//  object Keystore {
//    /**
//     * 새 PrivateKey를 생성하려면 자체 서명 인증서가 갖게 될 초기 X.509 특성도 지정해야 합니다.
//     * KeyStore.setKeyEntry를 사용하면 나중에 이 인증서를 CA(인증 기관)가 서명한 인증서로 바꿀 수 있습니다.
//     * 키를 생성하려면 KeyPairGenerator와 KeyPairGeneratorSpec을 함께 사용합니다.
//     */
//    @TargetApi(Build.VERSION_CODES.M)
//    fun generateKeyPair(keyAlias: String, algorithm: String = KeyProperties.KEY_ALGORITHM_EC): KeyPair {
//      /*
//       * Generate a new EC key pair entry in the Android Keystore by
//       * using the KeyPairGenerator API. The private key can only be
//       * used for signing or verification and only with SHA-256 or
//       * SHA-512 as the message digest.
//       */
//      val kpg = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore")
//      kpg.initialize(KeyGenParameterSpec.Builder(
//        keyAlias,
//        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//        .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
//        .build())
//      val kp = kpg.generateKeyPair()
//      return kp
//    }
//
//    /**
//     * - Generates the key pair with keystore(23+ TEE or SE)
//     *   https://developer.android.com/training/articles/keystore?hl=ko#SecurityFeatures
//     */
//    @TargetApi(Build.VERSION_CODES.M)
//    fun generateKeyPairWithRSA(keyAlias: String): KeyPair {
//      /*
//       * Generate a new EC key pair entry in the Android Keystore by
//       * using the KeyPairGenerator API. The private key can only be
//       * used for signing or verification and only with SHA-256 or
//       * SHA-512 as the message digest.
//       */
//      val kpg = KeyPairGenerator.getInstance(
//        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
//      kpg.initialize(KeyGenParameterSpec.Builder(
//        keyAlias,
//        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//        .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
//        .build())
//
//      val kp = kpg.generateKeyPair()
//      return kp
//    }
//
//    /**
//     * aliases() 메서드를 호출하여 키스토어에 항목을 나열합니다.
//     */
//    fun getKeyStoreList(): Enumeration<String> {
//      /*
//       * Load the Android KeyStore instance using the the
//       * "AndroidKeyStore" provider to list out what entries are
//       * currently stored.
//       */
//      val ks = KeyStore.getInstance("AndroidKeyStore")
//      ks.load(null)
//      val aliases = ks.aliases()
//      return aliases
//    }
//
//    /**
//     * 키스토어에서 KeyStore.Entry를 가져오고 sign()과 같은 Signature API를 사용하여 데이터에 서명합니다.
//     */
//    fun sign(data: String, keyAlias: String, algorithm: String = "SHA256withECDSA"): ByteArray? {
//      /*
//       * Use a PrivateKey in the KeyStore to create a signature over
//       * some data.
//       */
//      val ks = KeyStore.getInstance("AndroidKeyStore")
//      ks.load(null)
//      val entry = ks.getEntry(keyAlias, null)
//      if (entry !is KeyStore.PrivateKeyEntry) {
//        // Log.w(TAG, "Not an instance of a PrivateKeyEntry")
//        println(TAG + "Not an instance of a PrivateKeyEntry")
//        return null
//      }
//      val s = Signature.getInstance(algorithm)
//      s.initSign(entry.privateKey)
//      s.update(data.toByte())
//
//      return s.sign()
//    }
//
//    /**
//     * 마찬가지로, verify(byte[]) 메서드를 사용하여 데이터를 확인합니다.
//     */
//    fun verify(data: String, signature: ByteArray, keyAlias: String, algorithm: String = "SHA256withECDSA"): Boolean {
//      /*
//       * Verify a signature previously made by a PrivateKey in our
//       * KeyStore. This uses the X.509 certificate attached to our
//       * private key in the KeyStore to validate a previously
//       * generated signature.
//       */
//      val ks = KeyStore.getInstance("AndroidKeyStore")
//      ks.load(null)
//      val entry = ks.getEntry(keyAlias, null)
//      if (entry !is KeyStore.PrivateKeyEntry) {
//        // Log.w(TAG, "Not an instance of a PrivateKeyEntry")
//        println(TAG + "Not an instance of a PrivateKeyEntry")
//        return false
//      }
//      val s = Signature.getInstance(algorithm)
//      s.initVerify(entry.certificate)
//      s.update(data.toByte())
//
//      return s.verify(signature)
//    }
//  }
} // nSecurity end

/**
 * String security extension
 */
fun UUID.toUUID(): String {
  return UUID.randomUUID().toString().replace("-", "")
}

/**
 * Hash
 */
fun String.toBase64(): String {
  return Base64.encode(this.toByteArray())
}
fun String.toBase64Decode(): ByteArray {
  return Base64.decode(this)
}
fun String.toBase64DecodeString(): String {
  return String(Base64.decode(this))
}
fun String.toSha1(): String {
  return nSecurity.Hash.sha1(this)
}
fun String.toSha256(): String {
  return nSecurity.Hash.sha256(this)
}
fun String.toSha512(): String {
  return nSecurity.Hash.sha512(this)
}
fun ByteArray.toBase64(): String {
  return Base64.encode(this)
}


/**
 * Message
 */
fun String.toHmacSha1(key: String): String {
  return nSecurity.Hmac.hmacSha1(this, key)
}
fun String.toHmacSha256(key: String): String {
  return nSecurity.Hmac.hmacSha256(this, key)
}

/**
 * AES
 */
fun String.encryptAES(key: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.encrypt(this, key, transform)
}
fun String.encryptAES(key: String, iv: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.encrypt(this, key, iv, transform)
}
fun String.decryptAES(key: String/*base64*/, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.decrypt(this.toBase64Decode(), key, transform)
}
fun String.decryptAES(key: String/*base64*/, iv: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.decrypt(this.toBase64Decode(), key, iv, transform)
}
fun ByteArray.encryptAES(key: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.encrypt(this, key, transform)
}
fun ByteArray.encryptAES(key: String, iv: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.encrypt(this, key, iv, transform)
}
fun ByteArray.decryptAES(key: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.decrypt(this, key, transform)
}
fun ByteArray.decryptAES(key: String, iv: String, transform: nSecurity.AES.Tranform = nSecurity.AES.Tranform.AesCbcPKCS5Padding): String {
  return nSecurity.AES.decrypt(this, key, iv, transform)
}


/**
 * RSA
 */
fun String.encryptRSA(privateKey: String): String {
  return nSecurity.RSA.encrypt(this, privateKey)
}
fun String.encryptRSA(privateKey: PrivateKey): String {
  return nSecurity.RSA.encrypt(this, privateKey)
}
fun String.encryptRSA(publicKey: PublicKey): String {
  return nSecurity.RSA.encrypt(this, publicKey)
}
fun String.decryptRSA(publicKey: String): String {
  return nSecurity.RSA.decrypt(this, publicKey)
}
fun String.decryptRSA(publicKey: PublicKey): String {
  return nSecurity.RSA.decrypt(this, publicKey)
}
fun String.decryptRSA(privateKey: PrivateKey): String {
  return nSecurity.RSA.decrypt(this, privateKey)
}
fun PublicKey.keyBase64() = Base64.encode(this.encoded)!!
fun PrivateKey.keyBase64() = Base64.encode(this.encoded)!!

// Converts a string to a PublicKey object
fun String.toPublicKey(): PublicKey {
  val keyBytes: ByteArray = Base64.decode(this)
  val spec = X509EncodedKeySpec(keyBytes)
  val keyFactory = KeyFactory.getInstance(nSecurity.RSA.ALGORITHM)
  return keyFactory.generatePublic(spec)
}

// Converts a string to a PrivateKey object
fun String.toPrivateKey(): PrivateKey {
  val keyBytes: ByteArray = Base64.decode(this)
  val spec = PKCS8EncodedKeySpec(keyBytes)
  val keyFactory = KeyFactory.getInstance(nSecurity.RSA.ALGORITHM)
  return keyFactory.generatePrivate(spec)
}

fun String.sign(privateKey: String): String {
  return nSecurity.RSA.sign(this, privateKey)
}
fun String.sign(privateKey: PrivateKey): String {
  return nSecurity.RSA.sign(this, privateKey.keyBase64())
}
fun String.verify(signature: String, publicKey: String): Boolean {
  return nSecurity.RSA.verify(this, signature, publicKey)
}
fun String.verify(signature: String, publicKey: PublicKey): Boolean {
  return nSecurity.RSA.verify(this, signature, publicKey.keyBase64())
}