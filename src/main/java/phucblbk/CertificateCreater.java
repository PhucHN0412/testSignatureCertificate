package phucblbk;

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
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class CertificateCreater {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("privatekey.key"))){
            oos.writeObject(keyPair.getPrivate());
        }
        System.out.println("keyPairGenerator.toString()"+keyPairGenerator.getAlgorithm());
        System.out.println("keyPairGenerator.toString()"+keyPairGenerator.getProvider());
        System.out.println("Private key duoc luu vao privatekey.key");
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("Public Key Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Public Key Format: " + publicKey.getFormat());
        System.out.println("Public Key (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("Private Key Algorithm: " + privateKey.getAlgorithm());
        System.out.println("Private Key Format: " + privateKey.getFormat());

        System.out.println("Private Key (BASE64):" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        X500Name issuer = new X500Name("CN=Test Self-Signed Certificate");
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        System.out.println("Thư mục làm việc hiện tại: " + System.getProperty("user.dir"));
        try (FileOutputStream fos = new FileOutputStream("selfsignedcertificate.cer")) {
            fos.write(certificate.getEncoded());
        }
        String message = "Hello, Text Message";
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(message.getBytes());
        byte[] signature = sig.sign();

        try(FileOutputStream fos = new FileOutputStream("signature.sig")){
            fos.write(signature);
        }
        System.out.println("Chữ ký số đã được lưu vào signature.sig");
        System.out.println("Chứng thư số tự ký đã được tạo và lưu vào selfsignedcertificate.cer");
    }
}