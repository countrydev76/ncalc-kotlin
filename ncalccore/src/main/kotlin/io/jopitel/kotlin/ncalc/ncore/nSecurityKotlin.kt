package io.jopitel.kotlin.ncalc.ncore

/**
 *  . Homepage
 *    http://resonatebyjw.blogspot.kr/search?updated-min=2015-01-01T00:00:00-08:00&updated-max=2016-01-01T00:00:00-08:00&max-results=2
 *    http://aircook.tistory.com/category
 *
 */

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException
import com.sun.org.apache.xml.internal.security.utils.Base64

import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.*
import java.security.spec.*
import java.text.SimpleDateFormat
import java.util.*
import kotlin.experimental.and

object nSecurityKotlin {
  val DateDefaultFormat = "yyyy.MM.dd HH:mm:ss"
  val RSA = "RSA"
  val AES = "AES"
  val UTF8 = "UTF-8"
  val RSADefaultPadding = "RSA/ECB/PKCS1Padding"
  val AESDefaultPadding = "AES/CBC/PKCS5Padding"

  // 공개키
  // 개인키
  //            String strPublicKey = Common.byteArrayToHex(publicKey.getEncoded());
  //            String strPrivateKey = Common.byteArrayToHex(privateKey.getEncoded());
  //            rsaKeyPair[0] = strPublicKey;
  //            rsaKeyPair[1] = strPrivateKey;
  val createRSAKeyPair: Array<String?>
    get() {
      val rsaKeyPair = arrayOfNulls<String>(2)
      try {
        val keyPairGenerator = KeyPairGenerator.getInstance(RSA)
        keyPairGenerator.initialize(2048)

        val keyPair = keyPairGenerator.genKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val keySpec = X509EncodedKeySpec(publicKey.encoded)
        val keyFactory = KeyFactory.getInstance(RSA)
        val originalPublicKey = keyFactory.generatePublic(keySpec)
        val strPublicKey = Base64.encode(originalPublicKey.encoded)

        val keySpec1 = PKCS8EncodedKeySpec(privateKey.encoded)
        val keyFactory1 = KeyFactory.getInstance(RSA)
        val originalPrivateKey = keyFactory.generatePrivate(keySpec1)
        val strPrivateKey = Base64.encode(originalPrivateKey.encoded)

        rsaKeyPair[0] = strPublicKey
        rsaKeyPair[1] = strPrivateKey
      } catch (e: Exception) {
        e.printStackTrace()
      }

      return rsaKeyPair
    }


  fun generateKeyPair(): KeyPair? {
    var keyPair: KeyPair? = null
    try {
      val clsKeyPairGenerator = KeyPairGenerator.getInstance(RSA)
      clsKeyPairGenerator.initialize(2048)
      keyPair = clsKeyPairGenerator.genKeyPair()
    } catch (e: NoSuchAlgorithmException) {
      e.printStackTrace()
    }

    return keyPair
  }

  /**
   * Public Key로 암호화한 후 결과로 출력된 byte 배열을 Base64로 인코딩하여 String으로 변환하여 리턴함
   *
   * @param text      암호화할 텍스트
   * @param publicKey RSA 공개키
   * @return Base64로 인코딩된 암호화 문자열
   */
  fun encryptRSA(text: String, publicKey: PublicKey): String? {
    val bytes = text.toByteArray()
    var encryptedText: String? = null
    try {
      val cipher = Cipher.getInstance(RSA)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      encryptedText = Base64.encode(bytes)
      //encryptedText = new String(Base64.encodeToString(cipher.doFinal(bytes), Base64.DEFAULT));
    } catch (e: NoSuchAlgorithmException) {
      e.printStackTrace()
    } catch (e: NoSuchPaddingException) {
      e.printStackTrace()
    } catch (e: InvalidKeyException) {
      e.printStackTrace()
    }

    return encryptedText
  }

  /**
   * decode 시킨 후 RSA 비밀키(Private Key)를 이용하여 암호화된 텍스트를 원문으로 복호화
   */
  @Throws(Base64DecodingException::class)
  fun decryptRSA(encryptedText: String, privateKey: PrivateKey): String? {
    val bytes = Base64.decode(encryptedText)
    //byte[] bytes = Base64.decode(encryptedText.getBytes(), Base64.DEFAULT);
    var decryptedText: String? = null
    try {
      val cipher = Cipher.getInstance(RSA)
      cipher.init(Cipher.DECRYPT_MODE, privateKey)
      decryptedText = String(cipher.doFinal(bytes))
    } catch (e: NoSuchAlgorithmException) {
      e.printStackTrace()
    } catch (e: NoSuchPaddingException) {
      e.printStackTrace()
    } catch (e: InvalidKeyException) {
      e.printStackTrace()
    } catch (e: IllegalBlockSizeException) {
      e.printStackTrace()
    } catch (e: BadPaddingException) {
      e.printStackTrace()
    }

    return decryptedText
  }

  /**
   * RSA 공개키로부터 RSAPublicKeySpec 객체를 생성함
   *
   * @param publicKey 공개키
   * @return RSAPublicKeySpec spec
   */
  fun getRSAPublicKeySpec(publicKey: PublicKey): RSAPublicKeySpec? {
    var spec: RSAPublicKeySpec? = null
    try {
      spec = KeyFactory.getInstance(RSA).getKeySpec(publicKey, RSAPublicKeySpec::class.java)
    } catch (e: InvalidKeySpecException) {
      e.printStackTrace()
    } catch (e: NoSuchAlgorithmException) {
      e.printStackTrace()
    }

    return spec
  }

  /**
   * RSA 비밀키로부터 RSAPrivateKeySpec 객체를 생성함
   *
   * @param privateKey 비밀키
   * @return RSAPrivateKeySpec
   */
  fun getRSAPrivateKeySpec(privateKey: PrivateKey): RSAPrivateKeySpec? {
    var spec: RSAPrivateKeySpec? = null
    try {
      spec = KeyFactory.getInstance(RSA).getKeySpec(privateKey, RSAPrivateKeySpec::class.java)
    } catch (e: InvalidKeySpecException) {
      e.printStackTrace()
    } catch (e: NoSuchAlgorithmException) {
      e.printStackTrace()
    }

    return spec
  }

  /**
   * keyPair 값을 이용하여 PublicKey 객체를 생성함
   */
  fun getPublicKey(keyPair: KeyPair): PublicKey? {
    var publicKey: PublicKey? = null
    try {
      publicKey = keyPair.public
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return publicKey
  }

  /**
   * keyPair 값을 이용하여 PrivateKey 객체를 생성함
   */
  fun getPrivateKey(keyPair: KeyPair): PrivateKey? {
    var privateKey: PrivateKey? = null
    try {
      privateKey = keyPair.private
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return privateKey
  }

  /**
   * Created by JW on 15. 6. 16..
   *
   * from Android
   */
  fun hex2byte(s: String?): ByteArray? {
    if (s == null) return null
    val l = s.length
    if (l % 2 == 1) return null
    val b = ByteArray(l / 2)
    for (i in 0 until l / 2) {
      b[i] = Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16).toByte()
    }
    return b
  }

  fun byte2Hex(b: Byte): String {
    val HEX_DIGITS = arrayOf("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f")
    val nb = b and 0xFF.toByte()
    /**
     *  - 'shr'은 해결되지 않은 참조로 빨간색으로 표시됩니다.
     *    https://stackoverrun.com/ko/q/13119495
     *    -> nb shr 4 and 0xF -> nb.toInt() and 0xF
     */
    val i_1 = nb.toInt() shr 4 and 0xF
    val i_2 = nb and 0xF
    return HEX_DIGITS[i_1] + HEX_DIGITS[i_2.toInt()]
  }

  fun bytes2Hex(b: ByteArray): String {
    val sb = StringBuffer(b.size * 2)
    for (x in b.indices) {
      sb.append(byte2Hex(b[x]))
    }
    return sb.toString()
  }

  fun hexToByteArray(hex: String?): ByteArray? {
    if (hex == null || hex.length == 0) return null
    val ba = ByteArray(hex.length / 2)
    for (i in ba.indices) {
      ba[i] = Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16).toByte()
    }
    return ba
    //        return new java.math.BigInteger(hex, 16).toByteArray();
  }

  fun byteArrayToHex(ba: ByteArray?): String? {
    if (ba == null || ba.size == 0) return null
    val sb = StringBuffer(ba.size * 2)
    var hexNumber: String
    for (i in ba.indices) {
      hexNumber = "0" + Integer.toHexString(0xff and ba[i].toInt())
      sb.append(hexNumber.substring(hexNumber.length - 2))
    }
    return sb.toString()
    //        return new java.math.BigInteger(ba).toString(16);
  }

  fun getKeyForAES128(pushId: String): ByteArray? {
    val strKey = getPushIdParts16(pushId)
    return strKey?.toByteArray()
  }

  private fun getIVForAES128(pushId: String): String? {
    return getPushIdParts16(pushId)
  }

  private fun getPushIdParts16(pushId: String?): String? {
    var strKey: String? = null
    if (pushId == null) return null
    if (pushId.length < 16) {
      strKey = pushId
      val restCnt = 16 - pushId.length
      for (i in 0 until restCnt) {
        strKey = strKey!! + i.toString()
      }
    } else if (pushId.length >= 16) {
      strKey = pushId.substring(0, 16)
    }
    return strKey
  }

  /*
    public static String getEncryptAES(String message, String pushId) {
        String strRet = null;
        byte[] key = getKeyForAES128(pushId);
        String strIV = getIVForAES128(pushId);
        if ( key == null || strIV == null ) return null;
        try {
            SecretKey secureKey = new SecretKeySpec(key, AES);
            Cipher c = Cipher.getInstance(AESDefaultPadding);
            c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(strIV.getBytes()));
            byte[] encrypted = c.doFinal(message.getBytes(UTF8));
            strRet = byteArrayToHex(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strRet;
    }

    public static String getDecryptAES(String encrypted, String pushId) {
        String strRet = null;
        byte[] key = getKeyForAES128(pushId);
        String strIV = getIVForAES128(pushId);
        if (key == null || strIV == null) return null;
        try {
            SecretKey secureKey = new SecretKeySpec(key, AES);
            Cipher c = Cipher.getInstance(AESDefaultPadding);
            c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(strIV.getBytes(UTF8)));
            byte[] byteStr = hexToByteArray(encrypted);
            strRet = new String(c.doFinal(byteStr), UTF8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strRet;
    }

    public static String encrypt(String message, String pushId) throws Exception {
        if (pushId == null || pushId.length() == 0)
            return "";

        String instance = (key().length() == 24) ? "DESede/ECB/PKCS5Padding" : "DES/ECB/PKCS5Padding";
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(instance);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, getKey());
        String amalgam = ID;

        byte[] inputBytes1 = amalgam.getBytes("UTF8");
        byte[] outputBytes1 = cipher.doFinal(inputBytes1);
        sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
        String outputStr1 = encoder.encode(outputBytes1);
        return outputStr1;
    }
    */
  // 출처: http://nuninaya.tistory.com/463 [1.너니나야 이야기]

  fun getEncryptAES(message: String, pushId: String): String? {
    var strRet: String? = null
    val key = getKeyForAES128(pushId)
    val strIV = getIVForAES128(pushId)
    if (key == null || strIV == null) return null
    try {
      val secureKey = SecretKeySpec(key, AES)
      val c = Cipher.getInstance(AESDefaultPadding)
      c.init(Cipher.ENCRYPT_MODE, secureKey, IvParameterSpec(strIV.toByteArray()))
      val encrypted = c.doFinal(message.toByteArray(charset(UTF8)))
      //strRet = byteArrayToHex(encrypted);
      strRet = Base64.encode(encrypted)
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return strRet
  }

  fun getDecryptAES(encrypted: String, pushId: String): String? {
    var strRet: String? = null
    val key = getKeyForAES128(pushId)
    val strIV = getIVForAES128(pushId)
    if (key == null || strIV == null) return null
    try {
      val secureKey = SecretKeySpec(key, AES)
      val c = Cipher.getInstance(AESDefaultPadding)
      c.init(Cipher.DECRYPT_MODE, secureKey, IvParameterSpec(strIV.toByteArray(charset(UTF8))))
      //byte[] byteStr = hexToByteArray(encrypted);
      val byteStr = Base64.decode(encrypted)
      strRet = String(c.doFinal(byteStr))
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return strRet
  }

  fun getEncryptRSA(input: String, strPublicKey: String): String? {
    var strCipher: String? = null
    try {
      val baPublicKey = Base64.decode(strPublicKey)

      val publicKey = KeyFactory.getInstance(RSA).generatePublic(X509EncodedKeySpec(baPublicKey))
      val clsCipher = Cipher.getInstance(RSADefaultPadding)
      clsCipher.init(Cipher.ENCRYPT_MODE, publicKey)
      val baCipherData = clsCipher.doFinal(input.toByteArray())
      strCipher = Base64.encode(baCipherData)
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return strCipher
  }

  fun getDecryptRSA(input: String, strPrivateKey: String): String? {
    var strResult: String? = null
    try {
      val encrypted = Base64.decode(input)
      val baPrivateKey = Base64.decode(strPrivateKey)

      val privateKey = KeyFactory.getInstance(RSA).generatePrivate(PKCS8EncodedKeySpec(baPrivateKey))
      val clsCipher = Cipher.getInstance(RSADefaultPadding)
      clsCipher.init(Cipher.DECRYPT_MODE, privateKey)
      val baData = clsCipher.doFinal(encrypted)
      strResult = String(baData)
    } catch (e: Exception) {
      e.printStackTrace()
    }

    return strResult
  }

  fun convertDateLongToString(time: Long): String {
    val dayTime = SimpleDateFormat(DateDefaultFormat)
    val dateTime = Date(time)
    return dayTime.format(dateTime)
  }


  //    public static String getEncryptAES(String message) {
  //        String strRet = null;
  //        byte[] key = getKeyForAES128();
  //        if ( key == null ) return null;
  //        try {
  //            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
  //            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  ////            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
  ////            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
  ////            Cipher cipher = Cipher.getInstance("AES");
  //            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
  //            byte[] encrypted = cipher.doFinal(message.getBytes());
  //            strRet = byteArrayToHex(encrypted);
  //        } catch (Exception e) {
  //            e.printStackTrace();
  //        }
  //        return strRet;
  //    }
  //
  //    public static String getDecryptAES(String encrypted) {
  //        String strRet = null;
  //        byte[] key = getKeyForAES128();
  //        if ( key == null ) return null;
  //        try {
  //            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
  //            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  ////            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
  ////            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
  ////            Cipher cipher = Cipher.getInstance("AES");
  //            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
  //            byte[] original = cipher.doFinal(hexToByteArray(encrypted));
  //            strRet = new String(original);
  //        } catch (Exception e) {
  //            e.printStackTrace();
  //        }
  //        return strRet;
  //    }

  //    public static String[] getCreateRSAKeyPair() {
  //        String[] rsaKeyPair = new String[2];
  //        try {
  //            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
  //            keyPairGenerator.initialize(2048);
  //
  //            KeyPair keyPair = keyPairGenerator.genKeyPair();
  //            Key publicKey = keyPair.getPublic(); // 공개키
  //            Key privateKey = keyPair.getPrivate(); // 개인키
  //            String strPublicKey = Common.byteArrayToHex(publicKey.getEncoded());
  //            String strPrivateKey = Common.byteArrayToHex(privateKey.getEncoded());
  //            rsaKeyPair[0] = strPublicKey;
  //            rsaKeyPair[1] = strPrivateKey;
  //        } catch (Exception e) {
  //            e.printStackTrace();
  //        }
  //        return rsaKeyPair;
  //    }

  //    public static String getEncryptRSA(String input, String strPublicKey) {
  //        String strCipher = null;
  //        byte[] bytePublicKey = Common.hexToByteArray(strPublicKey);
  ////        byte[] bytePublicKey = Common.getBase64Decode(strPublicKey);
  //        try {
  //            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytePublicKey);
  //            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  //            PublicKey publicKey = keyFactory.generatePublic(keySpec);
  //            Cipher clsCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
  //            clsCipher.init(Cipher.ENCRYPT_MODE, publicKey);
  //            byte[] arrCipherData = clsCipher.doFinal(input.getBytes());
  //            strCipher = Common.byteArrayToHex(arrCipherData);
  ////            strCipher = Common.getBase64Encode(arrCipherData);
  //        } catch (Exception e) {
  //            e.printStackTrace();
  //        }
  //        return strCipher;
  //    }
  //
  //    public static String getDecryptRSA(String input, String strPrivateKey) {
  //        String strResult = null;
  //        byte[] encrypted = Common.hexToByteArray(input);
  //        byte[] bytePrivateKey = Common.hexToByteArray(strPrivateKey);
  //        try {
  //            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
  //            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  //            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
  //            Cipher clsCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
  //            clsCipher.init(Cipher.DECRYPT_MODE, privateKey);
  //            byte[] arrData = clsCipher.doFinal(encrypted);
  //            strResult = new String(arrData);
  //        } catch (Exception e) {
  //            e.printStackTrace();
  //        }
  //        return strResult;
  //    }
}