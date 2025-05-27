package phucblbk;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class SignAndVerifyPDF {
    public static void main(String[] args) throws Exception {
        // Đăng ký Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        // Đọc private key và chứng thư
        FileInputStream fis = new FileInputStream("privatekey.key");
        ObjectInputStream ois = new ObjectInputStream(fis);
        PrivateKey privateKey = (PrivateKey) ois.readObject();
        ois.close();

        FileInputStream certFis = new FileInputStream("selfsignedcertificate.cer");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certFis);
        certFis.close();

        String inputFile = "input.pdf";
        String outputFile = "signed.pdf";
        PDDocument document = PDDocument.load(new File(inputFile));

        PDSignature pdSignature = new PDSignature();
        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        pdSignature.setName("Test Signer");
        pdSignature.setLocation("Hanoi");
        pdSignature.setReason("Testing PDF Signature");
        pdSignature.setSignDate(java.util.Calendar.getInstance());

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

        document.addSignature(pdSignature, signatureOptions, new SignatureInterface() {
            @Override
            public byte[] sign(InputStream content) throws Exception {
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
                gen.addSignerInfoGenerator(signerInfoBuilder.build(
                        new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey),
                        new JcaX509CertificateHolder(certificate)));
                gen.addCertificates(new JcaCertStore(java.util.Arrays.asList(certificate)));

                byte[] contentBytes = content.readAllBytes();
                CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(contentBytes), true);
                return signedData.getEncoded();
            }
        });

        document.save(outputFile);
        document.close();
        System.out.println("Tệp PDF đã ký được lưu vào: " + outputFile);
        System.out.println("Thư mục làm việc hiện tại: " + System.getProperty("user.dir"));

        document = PDDocument.load(new File(outputFile));
        PDSignature signature = document.getSignatureDictionaries().get(0);
        byte[] signatureContent = signature.getContents(new FileInputStream(outputFile));
        byte[] signedContent = signature.getSignedContent(new FileInputStream(outputFile));

        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), signatureContent);
        SignerInformation signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        X509Certificate cert = (X509Certificate) cmsSignedData.getCertificates().getMatches(signerInfo.getSID()).iterator().next();

        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC")
                .build(cert);
        boolean isValid = signerInfo.verify(verifier);

        System.out.println("Chữ ký PDF hợp lệ: " + isValid);
        document.close();
    }
}