package example

import org.mindrot.jbcrypt.BCrypt;
import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

class Encode(
  var encryption: Encryption
) {

  constructor(): this(
    Encryption()
  )

  @Throws ( Exception::class  )
  fun encrypt(plainText: String): String { return encryption.encryptPasswordBased(plainText);}

  @Throws ( Exception::class  )
  fun decrypt(cipherText: String): String { return encryption.decryptPasswordBased(cipherText);}

  fun hashpw(pass: String): String {

    val stored = BCrypt.hashpw(pass, BCrypt.gensalt());

    try {

      return encrypt(stored);

    } catch (e: Exception) {

      return "";
    }
  }

  fun verify(pass :String, hash: String): Boolean {
      try{

        val newHash = decrypt(hash);

        return BCrypt.checkpw(pass, newHash);

    } catch (e: Exception) {
        return false;
    }
  }
}
