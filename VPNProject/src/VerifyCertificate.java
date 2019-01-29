import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;



public class VerifyCertificate {

    /*
    This class should be able to:
    1. Print the DN (Distinguished Name) of CA (certificate.pem)
    2. Print the DN of user (crscert.pem)
    3. Verify the CA certificate
    4. Verify the user certificate
    5. Print "Pass" if check 3 and 4 is successful
    6. Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
     */


    //get cert from a file (String arg)
    public static X509Certificate getCert(String arg) throws IOException, CertificateException {
        InputStream is = new FileInputStream(arg);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(is);
        is.close();
        return cert;
    }

    public static void verifyCert(X509Certificate CAcert, PublicKey keyofCA, X509Certificate usercert) throws Exception {
        try {
            CAcert.verify(keyofCA);
            usercert.verify(keyofCA);
            //check dates
            CAcert.checkValidity();
            usercert.checkValidity();
           // System.out.println("Pass");
        } catch (Exception e) {
          //  System.out.println("Fail");
           // System.out.println(e.toString());
        }
    }


    //get cert from a certificate encoded as a string
    public static X509Certificate convertCert(String encodedcert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        byte[] bytearray = Base64.decode(encodedcert);
        InputStream is = new ByteArrayInputStream(bytearray);
        return (X509Certificate) cf.generateCertificate(is);
   }

    public static String printDN(X509Certificate cert) {
        return cert.getSubjectDN().toString();
    }

    

    public static void main(String args[]) throws Exception {
        String CACert = args[0];
        String userCert = args[1];

        //Print DN
        System.out.println(printDN(getCert(CACert)));
        System.out.println(printDN(getCert(userCert)));

        //get public key of CA for verification
        PublicKey keyofCA = getCert(CACert).getPublicKey();

        //verify certificates
        verifyCert(getCert(CACert),keyofCA, getCert(userCert));

    }
}
