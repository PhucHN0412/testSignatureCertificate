package test;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertCreate {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048,new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("privatekey.key"))){
            oos.writeObject(keyPair.getPrivate());
        }
        X500Name issuer = new X500Name("CN=Test");
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis()-24 * 60 *60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis()+365 * 24 *60 *60 *1000L);
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,serial,notBefore,notAfter,subject, keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certificateBuilder.build(signer);
        X509Certificate certificate =new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        System.out.println("Thu muc duoc ki");
        try(FileOutputStream fos = new FileOutputStream("selfsignedincertificate.cer")){
            fos.write(certificate.getEncoded());
        }
        System.out.println("Cert da tao va luu vao tep selfsignedincertificate.cer" );
    }
}
