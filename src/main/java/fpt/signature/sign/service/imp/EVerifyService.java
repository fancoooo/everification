package fpt.signature.sign.service.imp;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import fpt.signature.sign.core.PdfSigner;
import fpt.signature.sign.core.ValidationUtils;
import fpt.signature.sign.core.Verify;
import fpt.signature.sign.ex.ConnectErrorException;
import fpt.signature.sign.ex.InvalidCerException;
import fpt.signature.sign.ex.NotFoundSignature;
import fpt.signature.sign.ex.NotFoundURL;
import fpt.signature.sign.ocsp.OCSPCertStatus;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.service.IEVerifyService;
import fpt.signature.sign.object.*;
import fpt.signature.sign.utils.Base64Utils;
import fpt.signature.sign.utils.HashUtils;
import fpt.signature.sign.utils.Utils;
import keystore.KeyAndCertChain;
import keystore.KeystoreFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Service;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class EVerifyService implements IEVerifyService {
    private final Verify verify = new Verify();
    @Override
    public List<VerifyResult> verifyPdf(byte[] data) throws Exception {
        List<VerifyResult> result = new ArrayList();
        PdfReader reader = null;

        try {
            reader = new PdfReader(data);
        } catch (IOException var26) {

        }

        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        if (names != null && !names.isEmpty()) {
            int index = 0;
            if (names.size() > 0) {
                Iterator var9 = names.iterator();

                while(var9.hasNext()) {
                    String name = (String)var9.next();

                    X509Certificate signerCertificate = null;
                    PdfPKCS7 pkcs7 = null;


                    try {
                        VerifyResult res = new VerifyResult();
                        result.add(res);
                        res.setCertStatus(ValidateStatus.UNKNOW.toString());
                        res.setSignatureIndex(index);
                        ++index;
                        boolean bResult = false;
                        try{
                            pkcs7 = af.verifySignature(name, "BC");
                            bResult = pkcs7.verify();

                        }catch (Exception ex){
                            //
                        }

                        res.setSignatureStatus(bResult);

                        Date  signingTime = pkcs7.getSignDate().getTime();
                        String algorithm = pkcs7.getHashAlgorithm();
                        signerCertificate = pkcs7.getSigningCertificate();

                        res.setEffectDate(signerCertificate.getNotBefore());
                        res.setExpriteDate(signerCertificate.getNotAfter());

                        X500Name x500SubjectName = new X500Name(new MobileIDX500NameStyle(), signerCertificate.getSubjectDN().toString());
                        String subjectDn = x500SubjectName.toString();

                        res.setSubjectDN(subjectDn);

                        X500Name x500IssuerName = new X500Name(new MobileIDX500NameStyle(), signerCertificate.getIssuerDN().toString());
                        String issuerDn = x500IssuerName.toString();

                        res.setIssuer(issuerDn);


                        String serialNumber = DatatypeConverter.printHexBinary(signerCertificate.getSerialNumber().toByteArray()).toLowerCase();
                        res.setSerialNumber(serialNumber);


                        res.setSigningTime(signingTime);

                        if (true) {
                            Certificate[] pkc = pkcs7.getCertificates();
                            Certificate[] var17 = pkc;
                            int var18 = pkc.length;

                            for(int var19 = 0; var19 < var18; ++var19) {
                                Certificate ob = var17[var19];
                                X509Certificate cert = (X509Certificate)ob;
                                if (cert.getBasicConstraints() == -1) {
                                    String certBase64 = new String(Base64.getEncoder().encode(cert.getEncoded()));
                                    res.setCertificate(certBase64);
                                    ValidateStatus status = ValidationUtils.checkValidTime(cert, null);
                                    if (ValidateStatus.GOOD == status) {
                                        OCSPCertStatus certStatus = this.verify.verifyCerOCSP(cert, null, null);
                                        res.setCertStatus(certStatus.toString());
                                        if (certStatus == OCSPCertStatus.GOOD) {
                                            res.setCode(VERIFY_RESULT.vefSigSucess.ordinal());
                                        } else {
                                            res.setCode(VERIFY_RESULT.vefCertNotGood.ordinal());
                                        }
                                    } else {
                                        res.setCertStatus(status.toString());
                                        res.setCode(VERIFY_RESULT.vefCheckCertFailed.ordinal());
                                    }
                                    break;
                                }
                            }
                        }
                    } catch (InvalidCerException var27) {
                        //Logger.getLogger(VerifyPDF.class.getName()).log(Level.SEVERE, (String)null, var27);
                    } catch (CertificateEncodingException var28) {
                        //Logger.getLogger(VerifyPDF.class.getName()).log(Level.SEVERE, (String)null, var28);
                    } catch (NotFoundURL var30) {
                        //Logger.getLogger(VerifyPDF.class.getName()).log(Level.SEVERE, (String)null, var30);
                    } catch (ConnectErrorException var31) {
                        //Logger.getLogger(VerifyPDF.class.getName()).log(Level.SEVERE, (String)null, var31);
                    }
                }
            }

            return result;
        } else {
            throw new NotFoundSignature();
        }
    }
}
