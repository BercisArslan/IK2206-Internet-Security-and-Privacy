import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


//Session key = symmetric key
public class SessionKey {

    private SecretKey secretKey;

    //first constructor creates a random SessionKey of the specified length (keylength) in bits.
    public SessionKey(Integer keylength) {

        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.init(keylength);
        this.secretKey = generator.generateKey();
    }

    //second creates SessionKey from string (encodekey).
    public SessionKey(String encodedkey) {
        byte[] decodeKey = Base64.getDecoder().decode(encodedkey);
        SecretKey key = new SecretKeySpec(decodeKey,"AES");
        this.secretKey = key;
    }

    public SessionKey(byte [] key){
        this.secretKey = new SecretKeySpec(key,"AES");
    }


    //method to retrieve SecretKey from a SessionKey object
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    //returns string with Base64 encoded key
    public String encodeKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}
