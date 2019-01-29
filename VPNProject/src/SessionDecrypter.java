import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;

public class SessionDecrypter {

    SessionKey decodedKey;
    IvParameterSpec decodedIV;
    Cipher cipher;

    //key and iv are Base64 encoded, so we decode them here first
    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.decodedKey = new SessionKey(key);
        this.decodedIV = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, this.decodedKey.getSecretKey(),this.decodedIV);
    }

    public SessionDecrypter(SessionKey sessionKey, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.decodedKey = sessionKey;
        this.decodedIV = IV;
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, this.decodedKey.getSecretKey(),this.decodedIV);
    }

    CipherInputStream openCipherInputStream(InputStream input){
        CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);
        return cipherInputStream;
    }
}
