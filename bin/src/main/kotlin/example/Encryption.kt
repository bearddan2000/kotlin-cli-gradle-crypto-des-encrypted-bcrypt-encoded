package example;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

class Encryption {

    val password = "abcd1234";
    val key = DESKeySpec(password.toByteArray());
    val keyFactory = SecretKeyFactory.getInstance("DES");
    val secretKey = keyFactory.generateSecret(key);

    @Throws ( Exception::class  )
    fun encryptPasswordBased(plainText :String) : String
    {
        val cipher :Cipher = Cipher.getInstance("DES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.toByteArray()))
    }

    @Throws ( Exception::class  )
    fun decryptPasswordBased(cipherText: String): String {
        val cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

}
