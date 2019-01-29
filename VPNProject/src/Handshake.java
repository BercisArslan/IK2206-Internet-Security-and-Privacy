import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Handshake {


    /* Where the client forwarder forwards data from: serverhost and serverport  */

    /* The final destination: targethost and targetport */


    /*Handshake protocol using HandshakeMessage class
    *
    * Need one handshake for clienthello message
    *
    * Need one handshake for serverhello message
    *
    * Need one forward message (from client to server)
    *
    * Need one session message (server to client)
    * */

    public static X509Certificate clientcert;
    public static X509Certificate servercert;
    public static X509Certificate ca;

    public static String targethost;
    public static int targetport;

    public static String serverhost;
    public static int serverport;

    public static SessionEncrypter sessionEncrypter;
    public static SessionDecrypter sessionDecrypter;
    public static PublicKey publickeyofclient;




    public static void hello(Socket socket, String cert, String value) throws IOException, CertificateException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        //Assign parameter and value
        handshakeMessage.putParameter("MessageType", value);
        handshakeMessage.putParameter("Certificate", Base64.encode(VerifyCertificate.getCert(cert).getEncoded()));
        handshakeMessage.send(socket);
    }

    public static void verifyhello(Socket socket, String cacert, String value) throws Exception {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        ca = VerifyCertificate.getCert(cacert);
        if (handshakeMessage.getParameter("MessageType").equals(value)) {
            if (value.equals("ClientHello")) {
                String clientcertstring = handshakeMessage.getParameter("Certificate");
                clientcert = VerifyCertificate.convertCert(clientcertstring);
                try {
                    VerifyCertificate.verifyCert(ca, ca.getPublicKey(), clientcert);
                } catch (Exception e) {
                }
            }
            if (value.equals("ServerHello")) {
                String servercertstring = handshakeMessage.getParameter("Certificate");
                servercert = VerifyCertificate.convertCert(servercertstring);
                try {
                    VerifyCertificate.verifyCert(ca, ca.getPublicKey(), servercert);
                } catch (Exception e) {
                }
            }
        } else {
            socket.close();
        }
    }
    //forward message from client to server
    public static void forward(Socket socket, String targethost, String targetport) throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", "Forward");
        handshakeMessage.putParameter("TargetHost",targethost);
        handshakeMessage.putParameter("TargetPort", targetport);
        handshakeMessage.send(socket);
    }

    public static void acceptforward(Socket socket) throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        if(handshakeMessage.getParameter("MessageType").equals("Forward")){
            targethost = handshakeMessage.getParameter("TargetHost");
            targetport = Integer.parseInt(handshakeMessage.getParameter("TargetPort"));
        }else{
            socket.close();
        }
    }
    //server creates session and sends session info to the client
    public static void session(Socket socket, String serverHost, String serverPort) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType","Session");

        //encrypt the key and iv before sending them to client with client public key.

        //get public key of client from certificate
        publickeyofclient = clientcert.getPublicKey();

        //create a session key of length 128
        //SessionKey sessionkey = new SessionKey(128);
        //create a IV for this session
        //IvParameterSpec IV = new IvParameterSpec(new SecureRandom().generateSeed(16));
        //encrypt key

        SessionEncrypter se = new SessionEncrypter(128);
        SessionKey sessionkey = se.getKey();
        IvParameterSpec IV = se.getIV();

        byte [] encryptkey = HandshakeCrypto.encrypt(sessionkey.getSecretKey().getEncoded(),publickeyofclient);
        //byte [] encryptkey = HandshakeCrypto.encrypt(sessionkey.encodeKey().getBytes(),publickeyofclient);
        //encrypt iv
        byte [] encryptiv = HandshakeCrypto.encrypt(IV.getIV(),publickeyofclient);
        //key and IV is now encrypted
        System.out.println(sessionkey.encodeKey());
        System.out.println(sessionkey.getSecretKey().getEncoded());
        System.out.println(Base64.encode(IV.getIV()));

        //we want a session encrypter from server side, derived from this key+IV pair
        sessionEncrypter = new SessionEncrypter(sessionkey,IV);
        sessionDecrypter = new SessionDecrypter(sessionkey,IV);

        //now we want to send them over encoded also with Base64
        handshakeMessage.putParameter("SessionKey", Base64.encode(encryptkey));
        handshakeMessage.putParameter("SessionIV", Base64.encode(encryptiv));
        handshakeMessage.putParameter("ServerHost",serverHost);
        handshakeMessage.putParameter("ServerPort",serverPort);
        handshakeMessage.send(socket);
    }

    public static void acceptsession(Socket socket, String privkey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        if(handshakeMessage.getParameter("MessageType").equals("Session")){
            String encodedkey = handshakeMessage.getParameter("SessionKey");
            String encodedIV = handshakeMessage.getParameter("SessionIV");
            serverhost = handshakeMessage.getParameter("ServerHost");
            serverport = Integer.parseInt(handshakeMessage.getParameter("ServerPort"));

            //Base64 decode the key and IV
            byte [] needdecryptkey = Base64.decode(encodedkey);
            byte [] needdecryptIV = Base64.decode(encodedIV);

            //get clients private key for decryption
            PrivateKey clientprivkey = HandshakeCrypto.getPrivateKeyFromKeyFile(privkey);
            //do the decryption
            byte [] decryptedfinalkey = HandshakeCrypto.decrypt(needdecryptkey,clientprivkey);
            byte [] decryptedfinaliv = HandshakeCrypto.decrypt(needdecryptIV,clientprivkey);

            System.out.println(new SessionKey((decryptedfinalkey)).encodeKey());
            System.out.println(Base64.encode(new IvParameterSpec (decryptedfinaliv).getIV()));

            //we want sessiondecrypter and decrypter from client side created from the derived key+IV pair
            sessionEncrypter = new SessionEncrypter(new SessionKey((decryptedfinalkey)), new IvParameterSpec(decryptedfinaliv));
            sessionDecrypter = new SessionDecrypter(new SessionKey((decryptedfinalkey)), new IvParameterSpec(decryptedfinaliv));

        }else{
            socket.close();
        }
    }

    public static String getTargethost(){
        return targethost;
    }

    public static int getTargetport(){
        return targetport;
    }

    public static String getServerhost(){
        return serverhost;
    }

    public static int getServerport(){
        return serverport;
    }

    public static SessionEncrypter getSessionEncrypter(){
        return sessionEncrypter;
    }

    public static SessionDecrypter getSessionDecrypter(){
        return sessionDecrypter;
    }
}