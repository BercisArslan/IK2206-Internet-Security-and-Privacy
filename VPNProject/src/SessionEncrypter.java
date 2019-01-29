import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.*;
import java.util.*;

public class SessionEncrypter {

    private SessionKey key;
    private IvParameterSpec IV;
    private Cipher cipher;

    public SessionEncrypter(Integer keylength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
            this.key = new SessionKey(keylength);
            this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte [] blockSizeByte = new byte[blockSize];
            Random rand = new SecureRandom();
            rand.nextBytes(blockSizeByte);
            this.IV = new IvParameterSpec(blockSizeByte);
            cipher.init(Cipher.ENCRYPT_MODE,this.key.getSecretKey(),this.IV);
    }

    public SessionEncrypter(SessionKey sessionKey, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.key = sessionKey;
        this.IV = IV;
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,this.key.getSecretKey(),this.IV);
    }

    public String encodeKey(){
        return this.key.encodeKey();
    }

    public String encodeIV(){
        return Base64.getEncoder().encodeToString(this.IV.getIV());
    }

    public SessionKey getKey(){
        return this.key;
    }
    public IvParameterSpec getIV(){
        return IV;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output){
        CipherOutputStream cipherOutputStream = new CipherOutputStream(output,cipher);
        return cipherOutputStream;
    }
}
