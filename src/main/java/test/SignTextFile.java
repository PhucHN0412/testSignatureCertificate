package test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
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
        fis.close();

        FileInputStream certFis = new FileInputStream("selfsignedincertificate.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFis);
        certFis.close();

        String textFile = "input.txt";
        FileInputStream textInputStream = new FileInputStream(textFile);
        byte[] textContent = textInputStream.readAllBytes();
        textContent.clone();

        Signature textSign = Signature.getInstance("SHA256withRSA");
        textSign.initSign(privateKey);
        textSign.update(textContent);
        byte[] textSignature = textSign.sign();

        try(FileOutputStream fos = new FileOutputStream("textSignature.sig")){
            fos.write(textSignature);
        }

        textInputStream = new FileInputStream(textFile);
        textContent = textInputStream.readAllBytes();
        textInputStream.close();

        FileInputStream textSigFis = new FileInputStream("textSignature.sig");
        byte[] textSignatureRead = textSigFis.readAllBytes();
        textSigFis.close();

        Signature verifyTextSig = Signature.getInstance("SHA256withRSA");
        verifyTextSig.initVerify(certificate.getPublicKey());
        verifyTextSig.update(textContent);
        boolean textValid = verifyTextSig.verify(textSignatureRead);
        System.out.println(textValid);
    }
}
