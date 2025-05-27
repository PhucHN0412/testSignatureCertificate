package phucblbk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SignTextFile {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        FileInputStream fis = new FileInputStream("privatekey.key");
        ObjectInputStream ois = new ObjectInputStream(fis);
        PrivateKey privateKey = (PrivateKey) ois.readObject();
        ois.close();

        FileInputStream certFis = new FileInputStream("selfsignedcertificate.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFis);
        certFis.close();

        String textFile = "input.txt";
        FileInputStream textInputStream = new FileInputStream(textFile);
        byte[] textContent = textInputStream.readAllBytes();
        textInputStream.close();

        Signature textSig = Signature.getInstance("SHA256withRSA");
        textSig.initSign(privateKey);
        textSig.update(textContent);
        byte[] textSignature = textSig.sign();

        try(FileOutputStream fos = new FileOutputStream("text_Signature.sig")){
            fos.write(textSignature);
        }
        System.out.println("Chu ky so van ban duoc luu vao text_Signature.sig");

        textInputStream = new FileInputStream(textFile);
        textContent = textInputStream.readAllBytes();
        textInputStream.close();
        FileInputStream textSigFis = new FileInputStream("text_Signature.sig");
        byte[] textSignatureRead = textSigFis.readAllBytes();
        textSigFis.close();

        Signature verifyTextSig = Signature.getInstance("SHA256withRSA");
        verifyTextSig.initVerify(certificate.getPublicKey());
        verifyTextSig.update(textContent);
        boolean textValid = verifyTextSig.verify(textSignatureRead);
        System.out.println("Chu ky hop le: "+textValid);
    }
}
