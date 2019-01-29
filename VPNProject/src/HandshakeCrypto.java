import javax.crypto.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

//Processes private keys in .der format
public class HandshakeCrypto {

    //Takes plaintext as byte array, and returns the corresponding cipher text as a byte array.
    //The key argument specifies the key, it can be a public or a private key.
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE,key);
        return c.doFinal(plaintext);
    }

    //Does the decryption
    public static byte[] decrypt(byte[] ciphertext,  Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE,key);
        return c.doFinal(ciphertext);
    }

    //Extract public key from a certificate file in .pem format
    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException {

        InputStream is = new FileInputStream(certfile);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(is);
        is.close();
        return cert.getPublicKey();
    }

    //Extract a private key from a keyfile
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] privateKey = Files.readAllBytes(Paths.get(keyfile));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }
}
