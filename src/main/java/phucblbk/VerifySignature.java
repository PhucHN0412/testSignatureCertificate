package phucblbk;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifySignature {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        FileInputStream fis = new FileInputStream("selfsignedcertificate.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
        fis.close();
        PublicKey publicKey = certificate.getPublicKey();

        FileInputStream sigFis = new FileInputStream("signature.sig");
        byte[] signature = sigFis.readAllBytes();
        sigFis.close();

        String message = "Hello,Text Message";

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        boolean isValid = sig.verify(signature);
        System.out.println("Chu ky hop le: "+ isValid);
    }


}
