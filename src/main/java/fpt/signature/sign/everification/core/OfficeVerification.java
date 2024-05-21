package fpt.signature.sign.everification.core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import fpt.signature.sign.everification.objects.ValidityResult;
import fpt.signature.sign.everification.objects.VerificationInternalResponse;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.poifs.crypt.Decryptor;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

public class OfficeVerification {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.OfficeVerification.class);

    private String lang;

    private String entityBillCode;

    private List<X509Certificate> registeredCerts;

    private String serialNumber;

    private boolean signerInformation;

    private boolean certificatesInformation;

    private boolean registeredConstraint;

    private boolean signedDataRequired;

    private String signingTimeTag;

    private String signingTimeFormat;

    private boolean officeDocument;

    private int acceptableCrlDuration;

    public OfficeVerification() {
        this.lang = "en";
        this.signerInformation = true;
    }

    public OfficeVerification(String lang, String entityBillCode, List<X509Certificate> registeredCerts, String serialNumber) {
        this.lang = lang;
        this.entityBillCode = entityBillCode;
        this.registeredCerts = registeredCerts;
        this.serialNumber = serialNumber;
    }

    public VerificationInternalResponse verify(byte[] document, String password, String billCode) {
        OPCPackage pkg;
        try {
            InputStream is = null;
            if (!Utils.isNullOrEmpty(password)) {
                is = new ByteArrayInputStream(document);
                POIFSFileSystem filesystem = new POIFSFileSystem(is);
                EncryptionInfo info = new EncryptionInfo(filesystem);
                Decryptor decryptor = Decryptor.getInstance(info);
                if (!decryptor.verifyPassword(password)) {
                    LOG.error("Office password maybe incorrect");
                    return new VerificationInternalResponse(5010, "Office password maybe incorrect", billCode);
                }
                InputStream dataStream = decryptor.getDataStream(filesystem);
                pkg = OPCPackage.open(dataStream);
                is.close();
            } else {
                is = new ByteArrayInputStream(document);
                pkg = OPCPackage.open(is);
                is.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Invalid office format. Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(5010, "Invalid office format", billCode);
        }
        try {
            SignatureConfig signatureConfig = new SignatureConfig();
            signatureConfig.setOpcPackage(pkg);
            SignatureInfo si = new SignatureInfo();
            si.setSignatureConfig(signatureConfig);
            List<ValidityResult> validityResults = new ArrayList<>();
            for (SignatureInfo.SignaturePart sp : si.getSignatureParts()) {
                String id = sp.getPackagePart().getPartName().getName();
                X509Certificate x509 = sp.getSigner();
                byte[] signedXMLData = sp.getSignatureDocument().xmlText().getBytes();
                XAdESVerification xadesVerification = new XAdESVerification(this.lang, this.entityBillCode, this.registeredCerts, this.serialNumber);
                xadesVerification.setCertificatesInformation(this.certificatesInformation);
                xadesVerification.setRegisteredConstraint(this.registeredConstraint);
                xadesVerification.setSignerInformation(this.signerInformation);
                xadesVerification.setSignedDataRequired(this.signedDataRequired);
                xadesVerification.setSigningTimeTag(this.signingTimeTag);
                xadesVerification.setSigningTimeFormat(this.signingTimeFormat);
                xadesVerification.setOfficeDocument(this.officeDocument);
                xadesVerification.setAcceptableCrlDuration(this.acceptableCrlDuration);
                VerificationInternalResponse xadesResp = xadesVerification.verify(signedXMLData, billCode);
                validityResults.add(xadesResp.getValidityResults().get(0));
            }
            if (validityResults.isEmpty()) {
                VerificationInternalResponse verificationInternalResponse1 = new VerificationInternalResponse();
                verificationInternalResponse1.setStatus(0);
                return verificationInternalResponse1;
            }
            VerificationInternalResponse verificationInternalResponse = new VerificationInternalResponse();
            verificationInternalResponse.setStatus(0);
            verificationInternalResponse.setMessage("SUCCESSFULLY");
            verificationInternalResponse.setValidityResults(validityResults);
            verificationInternalResponse.setResponse_bill_code(billCode);
            return verificationInternalResponse;
        } catch (Exception e) {
            LOG.error("Error while verifying office document. Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(5001);
        }
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

    public String getLang() {
        return this.lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getEntityBillCode() {
        return this.entityBillCode;
    }

    public void setEntityBillCode(String entityBillCode) {
        this.entityBillCode = entityBillCode;
    }

    public List<X509Certificate> getRegisteredCerts() {
        return this.registeredCerts;
    }

    public void setRegisteredCerts(List<X509Certificate> registeredCerts) {
        this.registeredCerts = registeredCerts;
    }

    public String getSerialNumber() {
        return this.serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSigningTimeTag() {
        return this.signingTimeTag;
    }

    public void setSigningTimeTag(String signingTimeTag) {
        this.signingTimeTag = signingTimeTag;
    }

    public String getSigningTimeFormat() {
        return this.signingTimeFormat;
    }

    public void setSigningTimeFormat(String signingTimeFormat) {
        this.signingTimeFormat = signingTimeFormat;
    }

    public void setOfficeDocument(boolean officeDocument) {
        this.officeDocument = officeDocument;
    }

    public int getAcceptableCrlDuration() {
        return this.acceptableCrlDuration;
    }

    public void setAcceptableCrlDuration(int acceptableCrlDuration) {
        this.acceptableCrlDuration = acceptableCrlDuration;
    }
}

