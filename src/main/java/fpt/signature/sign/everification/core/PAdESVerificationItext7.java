package fpt.signature.sign.everification.core;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfNumber;
import com.itextpdf.kernel.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.ReaderProperties;
import com.itextpdf.signatures.CRLVerifierEx;
import com.itextpdf.signatures.OCSPVerifierEx;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.bind.DatatypeConverter;
import fpt.signature.sign.everification.objects.*;
import fpt.signature.sign.general.RelyingParty;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import fpt.signature.sign.everification.objects.BasicOCSPRespComparable;
import fpt.signature.sign.everification.objects.CertDataValidation;
import fpt.signature.sign.everification.objects.X509CRLComparable;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.MobileIDX500NameStyle;
import fpt.signature.sign.utils.Utils;

public class PAdESVerificationItext7 {
    private static final String FORM_CMS = "CMS";

    private static final String FORM_PADES_B = "PAdES-B";

    private static final String FORM_PADES_T = "PAdES-T";

    private static final String FORM_PADES_LT = "PAdES-LT";

    private static final String FORM_PADES_LTA = "PAdES-LTA";

    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.PAdESVerificationItext7.class);

    private String lang;

    private String entityBillCode;

    private List<X509Certificate> registeredCerts;

    private String serialNumber;

    private boolean signerInformation;

    private boolean certificatesInformation;

    private boolean registeredConstraint;

    private boolean signedDataRequired;

    private int acceptableCrlDuration;

    static {
        Security.addProvider((Provider)new BouncyCastleProvider());
    }

    public PAdESVerificationItext7() {
        this.lang = "en";
        this.signerInformation = true;
        this.signedDataRequired = false;
    }

    public PAdESVerificationItext7(String lang, String entityBillCode, List<X509Certificate> registeredCerts, String serialNumber) {
        this.lang = lang;
        this.entityBillCode = entityBillCode;
        this.registeredCerts = registeredCerts;
        this.serialNumber = serialNumber;
    }

    public VerificationInternalResponse verify(byte[] document, String password, RelyingParty relyingParty, String billCode) {
        PdfReader reader = null;
        PdfDocument pdfDoc = null;
        SignatureUtil signatureUtil = null;
        ByteArrayOutputStream baos = null;
        PdfWriter writer = null;
        String ltvDescription = null;
        try {
            if (Utils.isNullOrEmpty(password)) {
                ByteArrayInputStream bais = new ByteArrayInputStream(document);
                reader = new PdfReader(bais);
                pdfDoc = new PdfDocument(reader.setUnethicalReading(true));
                bais.close();
            } else{
                ByteArrayInputStream bais = new ByteArrayInputStream(document);
                reader = new PdfReader(bais, (new ReaderProperties()).setPassword(password.getBytes()));
                pdfDoc = new PdfDocument(reader.setUnethicalReading(true));
                bais.close();
            }
        } catch (Exception e) {
            LOG.error("Invalid pdf format. Details: " + Utils.printStackTrace(e));
            closePdfReaderAndDocument(reader, pdfDoc);
            return new VerificationInternalResponse(2010, null, billCode);
        }
        signatureUtil = new SignatureUtil(pdfDoc);
        PdfDictionary dss = ((PdfDictionary)pdfDoc.getCatalog().getPdfObject()).getAsDictionary(PdfName.DSS);
        List<String> signatureNames = null;
        boolean tsaUsed = false;
        try {
            signatureNames = signatureUtil.getSignatureNames();
        } catch (Exception e) {
            LOG.error("Invalid pdf format. Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(2010);
        }
        int numberOfSignature = signatureNames.size();
        int fetchSignatureIndex = 0;
        Thread gettingDelSignThread = null;
        PdfSignatureManager pdfSignatureManager = null;
        if(relyingParty.getVerificationProperties().isShowSignatureDelete() || relyingParty.getVerificationProperties().isShowSignatureError()) {
            pdfSignatureManager = new PdfSignatureManager(document, password);
            gettingDelSignThread = new Thread((Runnable)pdfSignatureManager);
            gettingDelSignThread.start();
        }


        List<Date> listOfSigingTime = new ArrayList<>();
        if (signatureNames.isEmpty()) {
            closePdfReaderAndDocument(reader, pdfDoc);
            return new VerificationInternalResponse(0);
        }
        List<ValidityResult> validityResults = new ArrayList<>();
        boolean isTsp = false;
        boolean doLTV = false;
        for (String name : signatureNames) {
            fetchSignatureIndex++;
            ValidityResult validityResult = new ValidityResult();
            validityResult.setSignatureID(name);
            VerificationDetails verificationDetails = new VerificationDetails();
            boolean integrity = false;
            String signatureID = name;
            String signingForm = "CMS";
            Date signingTime = null;
            String signedData = null;
            boolean finalResult = true;
            Boolean registeredChecks = null;
            SignatureProperties signatureProperties = null;
            TSAChecks tsaChecks = null;
            X509Certificate signerCertificate = null;
            PdfPKCS7 pkcs7 = null;
            int pageNo = 0;
            try {
                pkcs7 = signatureUtil.readSignatureData(name, "BC");
                if (pkcs7.verifySignatureIntegrityAndAuthenticity())
                    integrity = true;
            } catch (Exception e) {
                LOG.error("Error while verifying pdf signature. Details: " + Utils.printStackTrace(e));
                verificationDetails.setIntegrity(Boolean.FALSE);
                validityResult.setVerificationDetails(verificationDetails);
                validityResults.add(validityResult);
                continue;
            }
            if (pkcs7.isTsp() &&
                    !isTsp)
                isTsp = true;
            signingTime = pkcs7.getSignDate().getTime();
            String algorithm = pkcs7.getHashAlgorithm();
            signerCertificate = pkcs7.getSigningCertificate();
            List<X509Certificate> x509CertList = new ArrayList<>();
            for (Certificate certificate : pkcs7.getSignCertificateChain())
                x509CertList.add((X509Certificate)certificate);
            if (x509CertList.size() > 1)
                try {
                    x509CertList = Crypto.sortX509Chain(x509CertList);
                } catch (Exception e) {
                    LOG.error("Error while sorting X509 certificate chain. Details: " + Utils.printStackTrace(e));
                    verificationDetails.setIntegrity(Boolean.FALSE);
                    validityResult.setVerificationDetails(verificationDetails);
                    validityResults.add(validityResult);
                    continue;
                }
            boolean timestapImprintResult = false;
            try {
                timestapImprintResult = pkcs7.verifyTimestampImprint();
            } catch (Exception e) {
                LOG.error("Error while verifying Timestamp Imprint. Details: " + Utils.printStackTrace(e));
                verificationDetails.setIntegrity(Boolean.valueOf(false));
                validityResult.setVerificationDetails(verificationDetails);
                validityResults.add(validityResult);
                continue;
            }
            validityResult.setTimestampEmbedded(false);
            if (timestapImprintResult) {
                validityResult.setTimestampEmbedded(true);
                tsaUsed = true;
                signingForm = "PAdES-T";
                TimeStampToken timeStampToken = pkcs7.getTimeStampToken();
                signingTime = timeStampToken.getTimeStampInfo().getGenTime();
                Store storeTt = timeStampToken.getCertificates();
                Collection collTt = storeTt.getMatches((Selector)timeStampToken.getSID());
                Collection<? extends X509CertificateHolder> tsaX509CertCollection = storeTt.getMatches(null);
                List<X509CertificateHolder> tsaHolders = new ArrayList<>();
                tsaHolders.addAll(tsaX509CertCollection);
                List<X509Certificate> tsaX509CertList = new ArrayList<>();
                JcaX509CertificateConverter tsaX509CertificateConverter = (new JcaX509CertificateConverter()).setProvider((Provider)new BouncyCastleProvider());
                for (X509CertificateHolder holder : tsaHolders) {
                    try {
                        tsaX509CertList.add(tsaX509CertificateConverter.getCertificate(holder));
                    } catch (CertificateException e) {
                        LOG.error("Cannot get X509Certificate from X509CertificateHolder. Details: " + Utils.printStackTrace(e));
                        verificationDetails.setIntegrity(Boolean.FALSE);
                        validityResult.setVerificationDetails(verificationDetails);
                        validityResults.add(validityResult);
                    }
                }
                try {
                    tsaX509CertList = Crypto.sortX509Chain(tsaX509CertList);
                } catch (Exception e) {
                    LOG.error("Error while sorting TSA X509 certificate chain. Details: " + Utils.printStackTrace(e));
                    verificationDetails.setIntegrity(Boolean.FALSE);
                    validityResult.setVerificationDetails(verificationDetails);
                    validityResults.add(validityResult);
                    continue;
                }
                Iterator<X509CertificateHolder> certIt2 = collTt.iterator();
                X509CertificateHolder cert2 = certIt2.next();
                tsaChecks = new TSAChecks();
                boolean tsaIntegrity = false;
                boolean tsaCertPathValidation = false;
                boolean tsaTrustedCertificate = false;
                try {
                    timeStampToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert2));
                    tsaIntegrity = true;
                } catch (Exception e) {
                    LOG.error("Failed to verify timestamp signature. Details: " + Utils.printStackTrace(e));
                }

                //tsaCertPathValidation = (new CertPathValidation()).validate(tsaX509CertList);
                //tsaTrustedCertificate = (new TrustedCertificateChecks()).validate(tsaX509CertList).isValid();
                //RevocationChecks tsaRevocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.valueOf(true), this.acceptableCrlDuration)).validate(tsaX509CertList.get(0), signingTime);
                //finalResult = (finalResult && tsaIntegrity && tsaCertPathValidation && tsaTrustedCertificate && tsaRevocationChecks.isSuccess());
                //tsaChecks.setIntegrity(Boolean.valueOf(tsaIntegrity));
                //tsaChecks.setCertPathValidation(Boolean.valueOf(tsaCertPathValidation));
                //tsaChecks.setTrustedCertificate(Boolean.valueOf(tsaTrustedCertificate));
                //tsaChecks.setRevocationChecks(tsaRevocationChecks);
            }

            boolean certPathValidation = (new CertPathValidation()).validate(x509CertList);
            Result trustedCheckResult = (new TrustedCertificateChecks()).validate(x509CertList);
            boolean trustedCertificate = trustedCheckResult.isValid();
            x509CertList = trustedCheckResult.getBuiltChain();
            if (x509CertList.size() == 1)
                LOG.error("Error while building chain of signer certificate " + signerCertificate.getSubjectDN().toString() + ". It maybe issued by un-trusted CA");
            CertDataValidation certDataValidationOfSignerCert = isLTVSignature(name, signatureUtil.getSignature(name), dss, pkcs7, signingTime, x509CertList);
            RevocationChecks revocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.TRUE, this.acceptableCrlDuration)).validate(x509CertList.get(0), signingTime);
            if (revocationChecks.getStatus().equals("FAILED") && certDataValidationOfSignerCert.isValid()) {
                LOG.error("Failed to check revocation status through CA's URL. Checking revocation status in LTV data");
                boolean checkRevocationBaseOnLTVOCSPOK = false;
                if (certDataValidationOfSignerCert.getBasicOCSPResp() != null) {
                    revocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.TRUE, this.acceptableCrlDuration)).validate(signerCertificate, signingTime, certDataValidationOfSignerCert.getBasicOCSPResp());
                    if (!revocationChecks.getStatus().equals("FAILED"))
                        checkRevocationBaseOnLTVOCSPOK = true;
                }
                if (!checkRevocationBaseOnLTVOCSPOK &&
                        certDataValidationOfSignerCert.getCrl() != null)
                    revocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.TRUE, this.acceptableCrlDuration)).validate(signerCertificate, signingTime, certDataValidationOfSignerCert.getCrl());
            }
            ValidityChecks validityChecks = (new ValidityStatusChecks(this.lang)).validate(x509CertList.get(0), signingTime);
            if (this.registeredCerts != null) {
                registeredChecks = Boolean.valueOf(this.registeredCerts.contains(x509CertList.get(0)));
            } else if (this.registeredConstraint) {
                registeredChecks = Boolean.FALSE;
            }
            if (!Utils.isNullOrEmpty(this.serialNumber))
                registeredChecks = this.serialNumber.compareToIgnoreCase(DatatypeConverter.printHexBinary(((X509Certificate) x509CertList.get(0)).getSerialNumber().toByteArray())) == 0;
            PdfDictionary dict = signatureUtil.getSignatureDictionary(name);
            TypeSig typeSig = checkSignatureType(name, dict);
            if ((typeSig.equals(TypeSig.SIGNATURE_NO_CHANGES_ALLOWED) || typeSig
                    .equals(TypeSig.CERTIFIED_NO_CHANGES_ALLOWED)) &&
                    fetchSignatureIndex != numberOfSignature) {
                LOG.debug("Signature " + name + " has type " + typeSig + " and it has been altered by next signature(s)");
                integrity = false;
            }
            verificationDetails.setIntegrity(integrity);
            verificationDetails.setCertPathValidation(certPathValidation);
            verificationDetails.setTrustedCertificate(trustedCertificate);
            verificationDetails.setRegisteredChecks(registeredChecks);
            verificationDetails.setRevocationChecks(revocationChecks);
            verificationDetails.setValidityChecks(validityChecks);

            verificationDetails.setRevocation(revocationChecks.isSuccess());
            verificationDetails.setValidity(validityChecks.isSuccess());

            if (registeredChecks == null) {
                //finalResult = (finalResult && integrity && certPathValidation && trustedCertificate && revocationChecks.isSuccess() && validityChecks.isSuccess());
                finalResult = integrity && trustedCertificate && revocationChecks.isSuccess() && validityChecks.isSuccess();
            } else {
                finalResult = integrity && trustedCertificate && revocationChecks.isSuccess() && validityChecks.isSuccess() && registeredChecks.booleanValue();
            }
            validityResult.setSigingForm(signingForm);
            validityResult.setSignatureID(signatureID);
            validityResult.setAlgorithm(algorithm);
            validityResult.setSigningTime(signingTime);
            validityResult.setSignatureType(typeSig.name());
            listOfSigingTime.add(signingTime);
            if (this.signedDataRequired)
                validityResult.setSignedData(signedData);
            validityResult.setSuccess(finalResult);
            validityResult.setVerificationDetails(verificationDetails);
            validityResult.setTsa(tsaChecks);
            if (this.signerInformation) {
                X500Name x500SubjectName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getSubjectDN().toString());
                String subjectDn = x500SubjectName.toString();
                X500Name x500IssuerName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getIssuerDN().toString());
                String issuerDn = x500IssuerName.toString();
                String thumbprint = null;
                try {
                    thumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getEncoded(), "SHA-1")).toLowerCase();
                } catch (CertificateEncodingException e) {
                    LOG.error("Cannot calculate certificate thumbprint. Details: " + Utils.printStackTrace(e));
                }
                String serialNumber = DatatypeConverter.printHexBinary(signerCertificate.getSerialNumber().toByteArray()).toLowerCase();
                String keyHash = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getPublicKey().getEncoded(), "SHA-1")).toLowerCase();
                validityResult.setSubject(subjectDn);
                validityResult.setIssuer(issuerDn);
                validityResult.setIssuer_cn(CertificatePolicy.getCommonName(issuerDn));
                validityResult.setSigner_cn(CertificatePolicy.getCommonName(subjectDn));
                validityResult.setThumbprint(thumbprint);
                validityResult.setSerialNumber(serialNumber);
                validityResult.setKeyHash(keyHash);
                validityResult.setValidFrom(signerCertificate.getNotBefore());
                validityResult.setValidTo(signerCertificate.getNotAfter());
                if (x509CertList.size() > 1) {
                    String issuerThumbprint = null;
                    String issuerSerialNumber = null;
                    String issuerKeyIdentifier = null;
                    String rootCAKeyIdentifier = null;
                    try {
                        issuerThumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(((X509Certificate)x509CertList.get(1)).getEncoded(), "SHA-1")).toLowerCase();
                        issuerSerialNumber = DatatypeConverter.printHexBinary(((X509Certificate)x509CertList.get(1)).getSerialNumber().toByteArray()).toLowerCase();
                        issuerKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(1));
                        if (Crypto.isRootCACertificate(x509CertList.get(x509CertList.size() - 1))) {
                            rootCAKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(x509CertList.size() - 1));
                        } else {
                            LOG.error("Bottom certificate in chain is not ROOT CA --> rootCAKeyIdentifier = NULL");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    validityResult.setIssuerSerialNumber(issuerSerialNumber);
                    validityResult.setIssuerKeyIdentifier(issuerKeyIdentifier);
                    validityResult.setRootCAKeyIdentifier(rootCAKeyIdentifier);
                    validityResult.setIssuerThumbprint(issuerThumbprint);
                }
            }
            if (this.certificatesInformation)
                try {
                    String certificateStr = DatatypeConverter.printBase64Binary(signerCertificate.getEncoded());
                    String[] chains = new String[x509CertList.size()];
                    List<String> l = new ArrayList<>();
                    for (X509Certificate certItem : x509CertList)
                        l.add(DatatypeConverter.printBase64Binary(certItem.getEncoded()));
                    chains = l.<String>toArray(chains);
                    validityResult.setCertificate(certificateStr);
                    validityResult.setChains(chains);
                } catch (CertificateEncodingException e) {
                    LOG.error("Cannot get certificate base64 encoded. Details: " + Utils.printStackTrace(e));
                }
            boolean setLtvOk = false;
            boolean ltvOcspEmbeddedInDocument = false;
            BasicOCSPResp ocspRespToBeEmbeddedInDocument = null;
            X509CRL crlRespToBeEmbeddedInDocument = null;
            validityResults.add(validityResult);
        }
        if(relyingParty.getVerificationProperties().isShowSignatureDelete() || relyingParty.getVerificationProperties().isShowSignatureError()) {
            List<ValidityResult> deletedSignatures = new ArrayList<>();
            List<StoreSignature.DataSignature> errorSignatures = new ArrayList<>();
            try {
                assert gettingDelSignThread != null;
                gettingDelSignThread.join();
                errorSignatures = pdfSignatureManager.getErrorSignatures();
                Map<PdfPKCS7, String> delSigs = pdfSignatureManager.getDeletedSignatures();
                if (delSigs != null &&
                        !delSigs.isEmpty())
                    for (Map.Entry<PdfPKCS7, String> entry : delSigs.entrySet()) {
                        String delSigName = entry.getValue();
                        PdfPKCS7 delPkcs7 = entry.getKey();
                        ValidityResult validityResult = new ValidityResult();
                        validityResult.setSigingForm("CMS");
                        validityResult.setSignatureID(delSigName);
                        validityResult.setAlgorithm(delPkcs7.getHashAlgorithm());
                        Date signingTime = null;
                        if (delPkcs7.getSignDate() != null)
                            signingTime = delPkcs7.getSignDate().getTime();
                        TimeStampToken timeStampToken = delPkcs7.getTimeStampToken();
                        if (timeStampToken != null)
                            signingTime = timeStampToken.getTimeStampInfo().getGenTime();
                        validityResult.setSigningTime(signingTime);
                        try {
                            validityResult.setSuccess(delPkcs7.verifySignatureIntegrityAndAuthenticity());
                        } catch (GeneralSecurityException ex) {
                            validityResult.setSuccess(Boolean.FALSE);
                        }
                        X509Certificate signerCertificate = delPkcs7.getSigningCertificate();
                        X500Name x500SubjectName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getSubjectDN().toString());
                        String subjectDn = x500SubjectName.toString();
                        X500Name x500IssuerName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getIssuerDN().toString());
                        String issuerDn = x500IssuerName.toString();
                        String thumbprint = null;
                        try {
                            thumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getEncoded(), "SHA-1")).toLowerCase();
                        } catch (CertificateEncodingException e) {
                            LOG.error("Cannot calculate certificate thumbprint. Details: " + Utils.printStackTrace(e));
                        }
                        String serialNumber = DatatypeConverter.printHexBinary(signerCertificate.getSerialNumber().toByteArray()).toLowerCase();
                        String keyHash = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getPublicKey().getEncoded(), "SHA-1")).toLowerCase();
                        validityResult.setSubject(subjectDn);
                        validityResult.setIssuer(issuerDn);
                        validityResult.setThumbprint(thumbprint);
                        validityResult.setSerialNumber(serialNumber);
                        validityResult.setKeyHash(keyHash);
                        validityResult.setValidFrom(signerCertificate.getNotBefore());
                        validityResult.setValidTo(signerCertificate.getNotAfter());
                        List<X509Certificate> x509CertList = new ArrayList<>();
                        for (Certificate certificate : delPkcs7.getSignCertificateChain())
                            x509CertList.add((X509Certificate)certificate);
                        try {
                            x509CertList = Crypto.sortX509Chain(x509CertList);
                            if (x509CertList.size() > 1) {
                                String issuerThumbprint = null;
                                String issuerSerialNumber = null;
                                String issuerKeyIdentifier = null;
                                String rootCAKeyIdentifier = null;
                                try {
                                    issuerThumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(((X509Certificate)x509CertList.get(1)).getEncoded(), "SHA-1")).toLowerCase();
                                    issuerSerialNumber = DatatypeConverter.printHexBinary(((X509Certificate)x509CertList.get(1)).getSerialNumber().toByteArray()).toLowerCase();
                                    issuerKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(1));
                                    if (Crypto.isRootCACertificate(x509CertList.get(x509CertList.size() - 1))) {
                                        rootCAKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(x509CertList.size() - 1));
                                    } else  {
                                        LOG.error("Bottom certificate in chain is not ROOT CA --> rootCAKeyIdentifier = NULL");
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                validityResult.setIssuerSerialNumber(issuerSerialNumber);
                                validityResult.setIssuerThumbprint(issuerThumbprint);
                                validityResult.setIssuerKeyIdentifier(issuerKeyIdentifier);
                                validityResult.setRootCAKeyIdentifier(rootCAKeyIdentifier);
                            }
                        } catch (Exception exception) {}
                        int size = pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getPageNumber().size();
                        SignatureProperties[] signatureProperties = new SignatureProperties[size];
                        for (int i = 0; i < size; i++) {
                            SignatureProperties signatureProperty = new SignatureProperties(((Integer)pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getPageNumber().get(i)).intValue(), new fpt.signature.sign.everification.objects.Rectangle(Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getRect()[0]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getRect()[1]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getRect()[2]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_PKCS7_Name.get(delPkcs7)).getRect()[3]).floatValue()));
                            signatureProperties[i] = signatureProperty;
                        }
                        VerificationDetails verificationDetails = new VerificationDetails();
                        validityResult.setVerificationDetails(verificationDetails);
                        validityResult.setStatus("SIGNATURE_DELETED");
                        LOG.debug("Found deleted signature " + delSigName);
                        deletedSignatures.add(validityResult);
                    }
            } catch (InterruptedException ex) {
                LOG.error("Get deleted signature interrupted error", ex);
            }
            if(relyingParty.getVerificationProperties().isShowSignatureDelete())
                for (ValidityResult vr : deletedSignatures) {
                    if (!this.signerInformation) {
                        vr.setSubject(null);
                        vr.setIssuer(null);
                        vr.setThumbprint(null);
                        vr.setSerialNumber(null);
                        vr.setIssuerThumbprint(null);
                        vr.setIssuerSerialNumber(null);
                        vr.setIssuerKeyIdentifier(null);
                        vr.setRootCAKeyIdentifier(null);
                        vr.setKeyHash(null);
                        vr.setValidFrom(null);
                        vr.setValidTo(null);
                    }
                    validityResults.add(vr);
                }
            if(relyingParty.getVerificationProperties().isShowSignatureError())
                for (StoreSignature.DataSignature es : errorSignatures) {
                    Map<String, String> v = es.getvField();
                    if (v != null && !v.isEmpty()) {
                        checkSignatureExistedAndRemoveIt(validityResults, (String)(pdfSignatureManager.getStorage()).map_Name_v.get(es));
                        ValidityResult vr = new ValidityResult();
                        vr.setSignatureID((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es));
                        vr.setSubject(v.get("Name"));
                        vr.setStatus("SIGNATURE_ERROR");
                        int size = pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getPageNumber().size();
                        SignatureProperties[] signatureProperties = new SignatureProperties[size];
                        for (int i = 0; i < size; i++) {
                            SignatureProperties signatureProperty = new SignatureProperties(((Integer)pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getPageNumber().get(i)).intValue(), new fpt.signature.sign.everification.objects.Rectangle(Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getRect()[0]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getRect()[1]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getRect()[2]).floatValue(), Float.valueOf(pdfSignatureManager.getStorePages().getPages((String)(pdfSignatureManager.getStorage()).map_Name_v.get(es)).getRect()[3]).floatValue()));
                            signatureProperties[i] = signatureProperty;
                        }
                        VerificationDetails verificationDetails = new VerificationDetails();
                        vr.setVerificationDetails(verificationDetails);
                        validityResults.add(vr);
                    }
                }
        }

        VerificationInternalResponse verificationInternalResponse = new VerificationInternalResponse();
        verificationInternalResponse.setStatus(0);
        verificationInternalResponse.setMessage("SUCCESSFULLY");
        verificationInternalResponse.setValidityResults(validityResults);
        verificationInternalResponse.setResponse_bill_code(billCode);
        if(relyingParty.getVerificationProperties().isShowAnntations()){
            Annotation[] anntations = getAnnotations(pdfDoc, listOfSigingTime);
            verificationInternalResponse.setAnntations(anntations);
        }
        closePdfReaderAndDocument(reader, pdfDoc);
        return verificationInternalResponse;
    }

    private Annotation[] getAnnotations(PdfDocument pdfDoc, List<Date> listOfSigningTime) {
        List<Annotation> annotations = new ArrayList<>();
        int numberOfPages = pdfDoc.getNumberOfPages();
        for (int i = 1; i <= numberOfPages; i++) {
            try {
                PdfDictionary pageDict = (PdfDictionary)pdfDoc.getPage(i).getPdfObject();
                PdfArray annotArray = pageDict.getAsArray(PdfName.Annots);
                PdfNumber pdfNumber = pageDict.getAsNumber(PdfName.Rotate);
                float pageWidth = pdfDoc.getPage(i).getPageSize().getWidth();
                float pageHeight = pdfDoc.getPage(i).getPageSize().getHeight();
                int degree = 0;
                if (pdfNumber != null)
                    degree = pdfNumber.intValue();
                if (annotArray != null)
                    for (int j = 0; j < annotArray.size(); j++) {
                        PdfDictionary curAnnot = annotArray.getAsDictionary(j);
                        if (curAnnot.getAsName(PdfName.FT) == null &&
                                curAnnot.getAsString(new PdfName("Subj")) != null) {
                            PdfArray annotRect = curAnnot.getAsArray(PdfName.Rect);
                            Annotation annotation = new Annotation();
                            annotation.setName((curAnnot.getAsString(PdfName.T) != null) ? curAnnot.getAsString(PdfName.T).toUnicodeString() : null);
                            annotation.setType(curAnnot.getAsString(new PdfName("Subj")).toUnicodeString());
                            annotation.setPage(i);
                            if (annotRect != null) {
                                Rectangle rect = rotateRect(pageWidth, pageHeight, new Rectangle(annotRect

                                        .getAsNumber(0).floatValue(), annotRect
                                        .getAsNumber(1).floatValue(), annotRect
                                        .getAsNumber(2).floatValue(), annotRect
                                        .getAsNumber(3).floatValue()), degree);
                                annotation.setRectangle(new fpt.signature.sign.everification.objects.Rectangle(rect
                                        .getX(), rect
                                        .getY(), rect
                                        .getX() + rect.getWidth(), rect
                                        .getY() + rect.getHeight()));
                            }
                            annotation.setContent((curAnnot.getAsString(PdfName.Contents) != null) ? curAnnot.getAsString(PdfName.Contents).toUnicodeString() : null);
                            Date createdDt = getPdfDateObject((curAnnot.getAsString(PdfName.CreationDate) != null) ? curAnnot.getAsString(PdfName.CreationDate).toUnicodeString() : null);
                            Date modifiedDt = getPdfDateObject((curAnnot.getAsString(PdfName.M) != null) ? curAnnot.getAsString(PdfName.M).toUnicodeString() : null);
                            annotation.setCreatedDt(createdDt);
                            annotation.setModifiedDt(modifiedDt);
                            annotation.setStatus("ANNOTATIONS_CREATED");
                            if (createdDt != null && modifiedDt != null)
                                for (Date st : listOfSigningTime) {
                                    if (createdDt.compareTo(st) < 0 && modifiedDt
                                            .compareTo(st) > 0)
                                        annotation.setStatus("ANNOTATIONS_MODIFIED");
                                }
                            annotations.add(annotation);
                        }
                    }
            } catch (Exception e) {
                LOG.error("Error while getting annotations. Details: " + Utils.printStackTrace(e));
            }
        }
        return annotations.<Annotation>toArray(new Annotation[0]);
    }




    public boolean isSignerInformation() {
        return this.signerInformation;
    }

    public void setSignerInformation(boolean signerInformation) {
        this.signerInformation = signerInformation;
    }

    public boolean isCertificatesInformation() {
        return this.certificatesInformation;
    }

    public void setCertificatesInformation(boolean certificatesInformation) {
        this.certificatesInformation = certificatesInformation;
    }

    public boolean isRegisteredConstraint() {
        return this.registeredConstraint;
    }

    public void setRegisteredConstraint(boolean registeredConstraint) {
        this.registeredConstraint = registeredConstraint;
    }

    public boolean isSignedDataRequired() {
        return this.signedDataRequired;
    }

    public void setSignedDataRequired(boolean signedDataRequired) {
        this.signedDataRequired = signedDataRequired;
    }

    public int getAcceptableCrlDuration() {
        return this.acceptableCrlDuration;
    }

    public void setAcceptableCrlDuration(int acceptableCrlDuration) {
        this.acceptableCrlDuration = acceptableCrlDuration;
    }

    private void closePdfReaderAndDocument(PdfReader reader, PdfDocument pdfDocument) {
        if (reader != null)
            try {
                reader.close();
            } catch (IOException iOException) {}
        if (pdfDocument != null)
            try {
                pdfDocument.close();
            } catch (Exception exception) {}
    }



    private Date getPdfDateObject(String str) {
        if (Utils.isNullOrEmpty(str))
            return null;
        str = str.substring(2);
        str = str.replace("'", "");
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssZ");
        try {
            return sdf.parse(str);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    public CertDataValidation isLTVSignature(String name, PdfSignature pdfSig, PdfDictionary dss, PdfPKCS7 pkcs7, Date signingTime, List<X509Certificate> certChain) {
        try {
            X509Certificate signingCertificate = pkcs7.getSigningCertificate();
            LOG.info("LTV checking for Signature Name " + name + ". Certificate " + signingCertificate.getSubjectDN().toString());
            X509Certificate issuerCertificate = null;
            if (certChain.size() == 1) {
                LOG.error("Only signer certificate in chain. It maybe issued by un-trusted CA --> Cannot check LTV signature");
                return new CertDataValidation();
            }
            X509Certificate mayItRootCA = certChain.get(certChain.size() - 1);
            if (!Crypto.isRootCACertificate(mayItRootCA)) {
                LOG.error("Chain contains signer certificate but RootCA is missing --> Cannot check LTV signature");
                return new CertDataValidation();
            }
            issuerCertificate = certChain.get(1);
            List<X509CRL> dssCrls = null;
            List<BasicOCSPResp> dssOcsps = null;
            List<X509Certificate> dssX509s = null;
            PdfDictionary vrim = null;
            if (dss != null) {
                PdfArray ocspsPdfArray = dss.getAsArray(PdfName.OCSPs);
                PdfArray crlsPdfArray = dss.getAsArray(PdfName.CRLs);
                PdfArray x509sPdfArray = dss.getAsArray(PdfName.Certs);
                vrim = dss.getAsDictionary(PdfName.VRI);
                if (crlsPdfArray != null)
                    dssCrls = getCRLsFromDSS(crlsPdfArray);
                if (ocspsPdfArray != null)
                    dssOcsps = getOCSPResponsesFromDSS(ocspsPdfArray);
                if (x509sPdfArray != null)
                    dssX509s = getX509CertificatesFromDSS(x509sPdfArray);
            }
            CertDataValidation certDataValidationOfSignerCert = isValidationDataValid(pdfSig, pkcs7, signingTime, signingCertificate, issuerCertificate, dssCrls, dssOcsps, dssX509s, vrim);
            boolean validValidationDataOfSignerCertificate = certDataValidationOfSignerCert.isValid();
            if (!validValidationDataOfSignerCertificate) {
                LOG.debug("No validation data of signer certificate in both DSS and signature ---> Make LTV signature name " + name + "\n");
                return new CertDataValidation();
            }
            for (int i = 0; i < certChain.size() - 1; i++) {
                if (Crypto.isCACertificate(certChain.get(i))) {
                    CertDataValidation certDataValidationOfCACert = isValidationDataValid(pdfSig, pkcs7, signingTime, certChain
                            .get(i), certChain.get(i + 1), dssCrls, dssOcsps, dssX509s, vrim);
                    boolean validValidationDataOfCACertificate = certDataValidationOfCACert.isValid();
                    if (!validValidationDataOfCACertificate) {
                        LOG.debug("No validation data of CA that issues the signer certificate in both DSS and signature ---> Make LTV signature name " + name + "\n");
                        return new CertDataValidation();
                    }
                }
            }
            return certDataValidationOfSignerCert;
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Cannot check LTV signature. Details: " + Utils.printStackTrace(e));
            return new CertDataValidation();
        }
    }

    private CertDataValidation isValidationDataValid(PdfSignature pdfSig, PdfPKCS7 pkcs7, Date signingTime, X509Certificate checkCert, X509Certificate issuerCert, List<X509CRL> dssCrls, List<BasicOCSPResp> dssOcsps, List<X509Certificate> dssX509s, PdfDictionary vrim) {
        LOG.debug("\n\n--------------------- Validate data of certificate " + checkCert.getSubjectDN().toString() + "\n");
        String checkCertCommonName = CertificatePolicy.getCommonName(checkCert.getSubjectDN().toString());
        boolean validValidationDataOfSignerCertificate = false;
        boolean embeddedInSignature = false;
        X509CRL crlResult = null;
        BasicOCSPResp ocspResult = null;
        Date ocspRespSignedAt = null;
        BasicOCSPResp basicOCSPResp = pkcs7.getOcsp();
        Collection<CRL> crlCollection = pkcs7.getCRLs();
        List<X509CRL> crlsInSignature = null;
        if (crlCollection != null) {
            crlsInSignature = new ArrayList<>();
            for (CRL crl : crlCollection)
                crlsInSignature.add((X509CRL)crl);
        }
        if (crlsInSignature == null) {
            LOG.debug("No CRL data of signer certificate " + checkCertCommonName + " in signature --> check in OCSP data in signature");
            validValidationDataOfSignerCertificate = false;
        } else {
            List<X509CRLComparable> x509CRLComparables = new ArrayList<>();
            CRLVerifierEx crlVerifier = new CRLVerifierEx(null, null);
            for (int i = crlsInSignature.size() - 1; i >= 0; i--) {
                try {
                    if (crlVerifier.verify(crlsInSignature.get(i), checkCert, issuerCert, signingTime))
                        x509CRLComparables.add(new X509CRLComparable(crlsInSignature.get(i), ((X509CRL)crlsInSignature.get(i)).getThisUpdate()));
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }
            }
            if (x509CRLComparables.isEmpty()) {
                LOG.error("No valid CRL data of certificate " + checkCertCommonName + " in signature --> check in OCSP data in signature");
                validValidationDataOfSignerCertificate = false;
            } else {
                Collections.sort(x509CRLComparables);
                crlResult = ((X509CRLComparable)x509CRLComparables.get(x509CRLComparables.size() - 1)).getX509Crl();
                LOG.debug("CRL data of certificate " + checkCertCommonName + " is OK in signature");
                validValidationDataOfSignerCertificate = true;
            }
        }
        if (!validValidationDataOfSignerCertificate)
            if (basicOCSPResp == null) {
                LOG.debug("No OCSP data of signer certificate " + checkCertCommonName + " in signature --> check in /DSS");
                validValidationDataOfSignerCertificate = false;
            } else {
                List<BasicOCSPRespComparable> basicOCSPRespComparables = new ArrayList<>();
                OCSPVerifierEx ocspVerifier = new OCSPVerifierEx(null, null);
                try {
                    if (ocspVerifier.verify(basicOCSPResp, crlsInSignature, checkCert, issuerCert, signingTime))
                        basicOCSPRespComparables.add(new BasicOCSPRespComparable(basicOCSPResp, basicOCSPResp.getProducedAt()));
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }
                if (!basicOCSPRespComparables.isEmpty()) {
                    Collections.sort(basicOCSPRespComparables);
                    ocspResult = ((BasicOCSPRespComparable)basicOCSPRespComparables.get(basicOCSPRespComparables.size() - 1)).getBasicOCSPResp();
                    ocspRespSignedAt = ((BasicOCSPRespComparable)basicOCSPRespComparables.get(basicOCSPRespComparables.size() - 1)).getProducedAt();
                    LOG.debug("OCSP data of certificate " + checkCertCommonName + " is OK in signature");
                    validValidationDataOfSignerCertificate = true;
                } else {
                    LOG.error("No valid OCSP data of certificate " + checkCertCommonName + " in signature --> check in /DSS");
                    validValidationDataOfSignerCertificate = false;
                }
            }
        if (!validValidationDataOfSignerCertificate) {
            if (dssOcsps == null && dssCrls == null && dssX509s == null) {
                LOG.debug("No validation data of signer certificate in DSS (dssOcsps == null && dssCrls == null && dssX509s == null)");
                return new CertDataValidation();
            }
            if (dssCrls != null) {
                List<X509CRLComparable> x509CRLComparables = new ArrayList<>();
                CRLVerifierEx crlVerifier = new CRLVerifierEx(null, null);
                for (int i = dssCrls.size() - 1; i >= 0; i--) {
                    try {
                        if (crlVerifier.verify(dssCrls.get(i), checkCert, issuerCert, signingTime))
                            x509CRLComparables.add(new X509CRLComparable(dssCrls.get(i), ((X509CRL)dssCrls.get(i)).getThisUpdate()));
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }
                }
                if (x509CRLComparables.isEmpty()) {
                    LOG.error("No valid CRL data of certificate " + checkCertCommonName + " in /DSS /CRLs");
                } else {
                    Collections.sort(x509CRLComparables);
                    crlResult = ((X509CRLComparable)x509CRLComparables.get(x509CRLComparables.size() - 1)).getX509Crl();
                    LOG.debug("CRL data of certificate " + checkCertCommonName + " is OK in /DSS /CRLs");
                }
            } else {
                LOG.debug("No /CRLs in /DSS");
            }
            if (dssOcsps != null) {
                List<BasicOCSPRespComparable> basicOCSPRespComparables = new ArrayList<>();
                OCSPVerifierEx ocspVerifier = new OCSPVerifierEx(null, null);
                for (int i = dssOcsps.size() - 1; i >= 0; i--) {
                    try {
                        if (ocspVerifier.verify(dssOcsps.get(i), dssCrls, checkCert, issuerCert, signingTime))
                            basicOCSPRespComparables.add(new BasicOCSPRespComparable(dssOcsps.get(i), ((BasicOCSPResp)dssOcsps.get(i)).getProducedAt()));
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }
                }
                if (!basicOCSPRespComparables.isEmpty()) {
                    Collections.sort(basicOCSPRespComparables);
                    ocspResult = ((BasicOCSPRespComparable)basicOCSPRespComparables.get(basicOCSPRespComparables.size() - 1)).getBasicOCSPResp();
                    ocspRespSignedAt = ((BasicOCSPRespComparable)basicOCSPRespComparables.get(basicOCSPRespComparables.size() - 1)).getProducedAt();
                    LOG.debug("OCSP data of certificate " + checkCertCommonName + " is OK in /DSS /OCSPs");
                } else {
                    LOG.error("No valid OCSP data of certificate " + checkCertCommonName + " in /DSS /OCSPs");
                }
            } else {
                LOG.debug("No /OCSPs in /DSS");
            }
            if (crlResult == null && ocspResult == null) {
                LOG.error("Certificate " + checkCertCommonName + " is missing both /OCSPs and /CRLs in /DSS");
                return new CertDataValidation();
            }
            if (dssX509s != null) {
                if (!dssX509s.contains(checkCert)) {
                    LOG.error("Missing certificate " + checkCert.getSubjectDN().toString() + " (SN=" + DatatypeConverter.printHexBinary(checkCert.getSerialNumber().toByteArray()) + ") in /DSS /Certs");
                    return new CertDataValidation();
                }
                if (!dssX509s.contains(issuerCert)) {
                    LOG.error("Missing certificate " + issuerCert.getSubjectDN().toString() + " (SN=" + DatatypeConverter.printHexBinary(issuerCert.getSerialNumber().toByteArray()) + ") in /DSS /Certs");
                    return new CertDataValidation();
                }
            } else {
                LOG.error("No /Certs in /DSS");
                return new CertDataValidation();
            }
            if (vrim != null) {
                PdfName signatureHashKey = null;
                try {
                    signatureHashKey = AdobeLtvEnabling.getSignatureHashKey(pdfSig);
                    boolean isSignatureHashKeyCheckOK = false;
                    LOG.debug("*************** SignatureHashKey: " + signatureHashKey);
                    Set<Map.Entry<PdfName, PdfObject>> sets = vrim.entrySet();
                    for (Map.Entry<PdfName, PdfObject> set : sets) {
                        PdfName key = set.getKey();
                        PdfObject value = set.getValue();
                        if (key.equals(signatureHashKey)) {
                            PdfDictionary vriSigPdict = (PdfDictionary)value;
                            PdfArray vriSigCrlPdfArray = vriSigPdict.getAsArray(PdfName.CRL);
                            List<X509CRL> vriCrls = getCRLsFromDSS(vriSigCrlPdfArray);
                            List<X509CRLComparable> x509CRLComparables = new ArrayList<>();
                            if (crlResult != null && ocspResult != null &&

                                    AdobeLtvEnabling.getOcspSignerCertificate(ocspResult.getEncoded())
                                            .getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null) {
                                if (vriSigCrlPdfArray == null) {
                                    LOG.error("No /CRL in /VRI");
                                    return new CertDataValidation();
                                }
                                CRLVerifierEx crlVerifier = new CRLVerifierEx(null, null);
                                for (int i = vriCrls.size() - 1; i >= 0; i--) {
                                    try {
                                        if (crlVerifier.verify(vriCrls.get(i), checkCert, issuerCert, signingTime))
                                            x509CRLComparables.add(new X509CRLComparable(vriCrls.get(i), ((X509CRL)vriCrls.get(i)).getThisUpdate()));
                                    } catch (GeneralSecurityException e) {
                                        e.printStackTrace();
                                    }
                                }
                                if (x509CRLComparables.isEmpty()) {
                                    LOG.error("No valid CRL data of certificate " + checkCertCommonName + " in /VRI /CRL");
                                    return new CertDataValidation();
                                }
                            }
                            PdfArray vriSigOcspPdfArray = vriSigPdict.getAsArray(PdfName.OCSP);
                            if (ocspResult != null) {
                                if (vriSigOcspPdfArray == null) {
                                    LOG.error("No /OCSP in /VRI");
                                    return new CertDataValidation();
                                }
                                List<BasicOCSPResp> vriOcsps = getOCSPResponsesFromDSS(vriSigOcspPdfArray);
                                List<BasicOCSPRespComparable> basicOCSPRespComparables = new ArrayList<>();
                                OCSPVerifierEx ocspVerifier = new OCSPVerifierEx(null, null);
                                for (int i = vriOcsps.size() - 1; i >= 0; i--) {
                                    try {
                                        if (ocspVerifier.verify(vriOcsps.get(i), dssCrls, checkCert, issuerCert, signingTime))
                                            basicOCSPRespComparables.add(new BasicOCSPRespComparable(vriOcsps.get(i), ((BasicOCSPResp)vriOcsps.get(i)).getProducedAt()));
                                    } catch (GeneralSecurityException e) {
                                        e.printStackTrace();
                                    }
                                }
                                if (basicOCSPRespComparables.isEmpty()) {
                                    LOG.error("No valid OCSP data of certificate " + checkCertCommonName + " in /VRI /OCSP");
                                    return new CertDataValidation();
                                }
                            }
                            PdfArray vriSigCertPdfArray = vriSigPdict.getAsArray(PdfName.Cert);
                            if (vriSigCertPdfArray != null) {
                                List<X509Certificate> vriSigCertX509List = getX509CertificatesFromDSS(vriSigCertPdfArray);
                                if (!vriSigCertX509List.contains(checkCert)) {
                                    LOG.error("Missing certificate " + checkCert.getSubjectDN().toString() + " (SN=" + DatatypeConverter.printHexBinary(checkCert.getSerialNumber().toByteArray()) + ") in /VRI /Cert");
                                    return new CertDataValidation();
                                }
                                if (!vriSigCertX509List.contains(issuerCert)) {
                                    LOG.error("Missing certificate " + issuerCert.getSubjectDN().toString() + " (SN=" + DatatypeConverter.printHexBinary(issuerCert.getSerialNumber().toByteArray()) + ") in /VRI /Cert");
                                    return new CertDataValidation();
                                }
                                LOG.debug("Certificate data of certificate " + checkCertCommonName + " is OK in /VRI /Cert");
                            } else {
                                LOG.debug("/VRI /Cert is NULL --> No check certs in this field");
                            }
                            PdfString tuString = vriSigPdict.getAsString(PdfName.TU);
                            if (tuString != null) {
                                LOG.debug("/VRI /TU " + tuString.getValue());
                            } else {
                                LOG.error("Certificate " + checkCertCommonName + " is missing /TU in /VRI /TU");
                                return new CertDataValidation();
                            }
                            validValidationDataOfSignerCertificate = true;
                            isSignatureHashKeyCheckOK = true;
                            break;
                        }
                    }
                    if (!isSignatureHashKeyCheckOK) {
                        LOG.error("No SignatureHashKey " + signatureHashKey + " in /VRI");
                        return new CertDataValidation();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    Utils.printStackTrace(e);
                }
            } else {
                LOG.error("No /VRI in /DSS");
                return new CertDataValidation();
            }
        }
        return new CertDataValidation(validValidationDataOfSignerCertificate, embeddedInSignature, crlResult, ocspResult, ocspRespSignedAt);
    }

    private List<X509CRL> getCRLsFromDSS(PdfArray crlarray) {
        CertificateFactory cf;
        List<X509CRL> crls = new ArrayList<>();
        if (crlarray == null)
            return crls;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            LOG.debug("Error while instancing CRL CertificateFactory. Details: " + Utils.printStackTrace(e));
            return crls;
        }
        for (int i = 0; i < crlarray.size(); i++) {
            try {
                PdfStream stream = crlarray.getAsStream(i);
                X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(stream.getBytes()));
                crls.add(crl);
            } catch (Exception e) {}
        }
        return crls;
    }

    private List<BasicOCSPResp> getOCSPResponsesFromDSS(PdfArray ocsparray) {
        List<BasicOCSPResp> ocsps = new ArrayList<>();
        for (int i = 0; i < ocsparray.size(); i++) {
            try {
                PdfStream stream = ocsparray.getAsStream(i);
                OCSPResp ocspResponse = new OCSPResp(stream.getBytes());
                if (ocspResponse.getStatus() == 0)
                    ocsps.add((BasicOCSPResp)ocspResponse.getResponseObject());
            } catch (Exception e) {}
        }
        return ocsps;
    }

    private List<X509Certificate> getX509CertificatesFromDSS(PdfArray x509array) {
        List<X509Certificate> x509s = new ArrayList<>();
        for (int i = 0; i < x509array.size(); i++) {
            try {
                PdfStream stream = x509array.getAsStream(i);
                CertificateFactory certFactoryChild = CertificateFactory.getInstance("X.509", "BC");
                InputStream inChild = new ByteArrayInputStream(stream.getBytes());
                x509s.add((X509Certificate)certFactoryChild.generateCertificate(inChild));
            } catch (Exception e) {}
        }
        return x509s;
    }

    private boolean checkSignatureExistedAndRemoveIt(List<ValidityResult> validityResults, String signatureID) {
        if (validityResults != null && !validityResults.isEmpty())
            for (ValidityResult vr : validityResults) {
                if (vr.getSignatureID().equals(signatureID)) {
                    validityResults.remove(vr);
                    return true;
                }
            }
        return false;
    }

    private TypeSig checkSignatureType(String name, PdfDictionary dict) {
        Status stat = new Status(this, name);
        if (!dict.containsKey(PdfName.Reference))
            return TypeSig.SIGNATURE;
        PdfArray reference = dict.getAsArray(PdfName.Reference);
        for (int i = 0; i < reference.size(); i++) {
            PdfDictionary tranformData = reference.getAsDictionary(i);
            if (tranformData.containsKey(PdfName.TransformParams)) {
                PdfName method = tranformData.getAsName(PdfName.TransformMethod);
                if (method.getValue().equals("DocMDP")) {
                    PdfDictionary transformParams = tranformData.getAsDictionary(PdfName.TransformParams);
                    PdfNumber num = transformParams.getAsNumber(PdfName.P);
                    stat.isCertified = true;
                    stat.setTypeCertified(num.intValue());
                }
                if (method.getValue().equals("FieldMDP")) {
                    PdfDictionary transformParams = tranformData.getAsDictionary(PdfName.TransformParams);
                    PdfNumber num = transformParams.getAsNumber(PdfName.P);
                    if (num != null)
                        stat.isLocked = true;
                }
            }
        }
        if (stat.typeCertified == null) {
            if (stat.isLocked)
                return TypeSig.SIGNATURE_NO_CHANGES_ALLOWED;
            return TypeSig.SIGNATURE;
        }
        return stat.typeCertified;
    }

    public static Rectangle rotateRect(float pageWidth, float pageHeight, Rectangle point, int degree) {
        float Ax = point.getX();
        float Ay = point.getY();
        float Bx = point.getWidth();
        float By = point.getHeight();
        float X = 0.0F;
        float Y = 0.0F;
        float width = Bx - Ax;
        float height = By - Ay;
        if (degree == 270) {
            X = pageHeight - By;
            Y = Ax;
            width = By - Ay;
            height = Bx - Ax;
        }
        if (degree == 0) {
            X = Ax;
            Y = Ay;
        }
        if (degree == 90) {
            X = Ay;
            Y = pageWidth - Ax - width;
            width = By - Ay;
            height = Bx - Ax;
        }
        if (degree == 180) {
            X = pageWidth - Ax - width;
            Y = pageHeight - Ay - height;
        }
        return new Rectangle(X, Y, width, height);
    }

    class Status {
        public String sigName;
        public TypeSig typeCertified;
        public boolean isCertified;
        public boolean isLocked;
        // $FF: synthetic field
        final PAdESVerificationItext7 this$0;

        public Status(PAdESVerificationItext7 var1, String name) {
            this.this$0 = var1;
            this.sigName = name;
        }

        public void setTypeCertified(int i) {
            if (i == 0) {
                if (this.isLocked) {
                    this.typeCertified = TypeSig.SIGNATURE_NO_CHANGES_ALLOWED;
                } else {
                    this.typeCertified = TypeSig.SIGNATURE;
                }
            }

            if (i == 1) {
                this.typeCertified = TypeSig.CERTIFIED_NO_CHANGES_ALLOWED;
            }

            if (i == 2) {
                this.typeCertified = TypeSig.CERTIFIED_FORM_FILLING_SIGNING;
            }

            if (i == 3) {
                this.typeCertified = TypeSig.CERTIFIED_FORM_FILLING_SIGNING_COMMENTING;
            }

        }
    }
}

