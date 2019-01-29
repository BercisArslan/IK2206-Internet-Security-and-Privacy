import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyTest {

    @Test
    void equal(){
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        assertEquals(key1.getSecretKey(),key2.getSecretKey());
    }

    @Test
    void testBits(){
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(192);
        SessionKey key3 = new SessionKey(256);
        //jämför att längden av byte array av secretkey (i bitar) är 128 lång
        assertEquals(key1.getSecretKey().getEncoded().length*8,128);
        assertEquals(key2.getSecretKey().getEncoded().length*8,192);
        assertEquals(key3.getSecretKey().getEncoded().length*8,256);

        System.out.println("128 bit key: " + key1.encodeKey());
        System.out.println("192 bit key: " + key2.encodeKey());
        System.out.println("256 bit key: " + key3.encodeKey());
    }
}