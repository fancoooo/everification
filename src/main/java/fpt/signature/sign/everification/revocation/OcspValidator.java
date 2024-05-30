package fpt.signature.sign.everification.revocation;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import fpt.signature.sign.everification.core.TrustedCertificateChecks;
import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.everification.objects.Endpoint;
import fpt.signature.sign.everification.objects.Result;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.security.ApplicationContextProvider;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.lang.NotImplementedException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class OcspValidator {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.revocation.OcspValidator.class);

    private final String entityBillCode;

    public OcspValidator(String entityBillCode) {
        this.entityBillCode = entityBillCode;
    }

    public ValidationResp check(X509Certificate issuerCert, X509Certificate cert) {
        Resources resources = ApplicationContextProvider.getApplicationContext().getBean(Resources.class);
        if (Crypto.isRootCACertificate(cert)) {
            LOG.debug("No check revocation status for RootCA (" + CertificatePolicy.getCommonName(cert.getSubjectDN().toString()) + ") certificate");
            return new ValidationResp(0, 0, null);
        }
        String commonNameOfCheckCert = CertificatePolicy.getCommonName(cert.getSubjectDN().toString());
        if (issuerCert.equals(cert)) {
            LOG.debug("No check revocation status for selfsign (RootCA) (" + CertificatePolicy.getCommonName(cert.getSubjectDN().toString()) + ") certificate");
            return new ValidationResp(0, 0, null);
        }
        String issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(cert);
        CertificationAuthority certificationAuthority = null;
        if (Utils.isNullOrEmpty(issuerKeyIdentifier)) {
            LOG.warn("issuerKeyIdentifier of certificate " + CertificatePolicy.getCommonName(cert.getSubjectDN().toString() + " is NULL"));
            List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
            for (CertificationAuthority ca : listOfCertificationAuthority) {
                if (ca.getCommonName().compareTo(Objects.requireNonNull(CertificatePolicy.getCommonName(cert.getIssuerDN().toString()))) == 0) {
                    X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                    try {
                        cert.verify(x509OfCA.getPublicKey());
                        certificationAuthority = ca;
                        break;
                    } catch (Exception exception) {}
                }
            }
            if (certificationAuthority == null) {
                resources.reloadCertificationAuthorities();
                listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
                for (CertificationAuthority ca : listOfCertificationAuthority) {
                    if (ca.getCommonName().compareTo(Objects.requireNonNull(CertificatePolicy.getCommonName(cert.getIssuerDN().toString()))) == 0) {
                        X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                        try {
                            cert.verify(x509OfCA.getPublicKey());
                            certificationAuthority = ca;
                            break;
                        } catch (Exception exception) {}
                    }
                }
            }
        } else {
            certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            if (certificationAuthority == null) {
                resources.reloadCertificationAuthorities();
                certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            }
        }
        if (certificationAuthority == null) {
            LOG.error("Cannot find CA with issuerKeyIdentifier: " + issuerKeyIdentifier);
            return new ValidationResp(5001);
        }
        CAProperties caProperties = certificationAuthority.getCaProperties();
        if (caProperties == null) {
            LOG.error("CAProperties is NULL. Cannot check OCSP");
            return new ValidationResp(5001);
        }
        OCSPResp ocspResponse = null;
        try {
            // lấy đường dẫn ocsp từ cert
            List<String> ocspUris = Crypto.getOcspUris(cert);
            assert ocspUris != null;
            if (Utils.isNullOrEmpty(ocspUris.get(0))) {
                LOG.debug("No OCSP URL found in certificate " + cert.getSubjectDN().toString() + ". This certificate could be SubCA");
                return new ValidationResp(5001);
            }
            OcspInvocation ocspInvocation = new OcspInvocation();
            ValidationReq validationReq = new ValidationReq();
            validationReq.setRetry(certificationAuthority.getCaProperties().getOcsp().getRetry());
            validationReq.setOcspUris(ocspUris);
            OCSPReq request = generateOCSPRequest(issuerCert, cert.getSerialNumber());
            byte[] array = request.getEncoded();
            validationReq.setOcspRequestData(array);
            ValidationResp validationResp = ocspInvocation.call(validationReq);
            if (validationResp.getResponseCode() == 0) {
                ocspResponse = new OCSPResp(validationResp.getOcspResponseData());
            } else {
                LOG.error("Error while checking ocsp status due to connection (HTTP != 200)");
                return new ValidationResp(5001);
            }
        } catch (Exception e) {
            LOG.error("Error while generate OCSP request. Details: " + Utils.printStackTrace(e));
            return new ValidationResp(5001);
        }
        try {
            BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResponse.getResponseObject();
            if (basicResponse.getResponses() != null)
                try {
                    X509Certificate ocspSigner = null;
                    X509CertificateHolder[] x509CertificateHolder = basicResponse.getCerts();
                    ocspSigner = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(x509CertificateHolder[0]);
                    boolean validOcspSignature = basicResponse.isSignatureValid((new JcaContentVerifierProviderBuilder())
                            .setProvider("BC").build(ocspSigner.getPublicKey()));
                    if (!validOcspSignature) {
                        LOG.error("Invalid Ocsp siganture. Please check with CA provider");
                        return new ValidationResp(5001, 3);
                    }
                    Result trustedCheckResult = (new TrustedCertificateChecks()).validate(Arrays.asList(new X509Certificate[] { ocspSigner }));
                    if (!trustedCheckResult.isValid()) {
                        LOG.error("Check OCSP status for certificate " + cert.getSubjectDN().toString() + " <--- Invalid Ocsp response due to OCSP Signer certificate is issued by un-trusted CA. Issuer CA: " + ocspSigner.getIssuerDN().toString());
                        return new ValidationResp(5001, 3);
                    }
                    LOG.debug("Check OCSP status for certificate " + cert.getSubjectDN().toString() + " <--- Ocsp response is signed by trusted CA or a signer issued by trusted CA. Subject of OCSP signer: " + ocspSigner.getSubjectDN().toString());
                    boolean hasIdPkixOcspNoCheckExtension = false;
                    if (Crypto.hasIdPkixOcspNoCheckExtension(ocspSigner)) {
                        hasIdPkixOcspNoCheckExtension = true;
                    } else if (!Crypto.isCACertificate(ocspSigner)) {
                        LOG.debug("id_pkix_ocsp_nocheck extension not found in OCSP signer certificate");
                    }
                    SingleResp[] responses = basicResponse.getResponses();
                    SingleResp resp = responses[0];
                    Object status = resp.getCertStatus();
                    if (status instanceof RevokedStatus) {
                        LOG.debug("OCSP Result of certificate " + commonNameOfCheckCert + ": REVOKED");
                        ValidationResp validationResp1 = new ValidationResp(0, 1, ((RevokedStatus)status).getRevocationTime());
                        validationResp1.setOcspResponseData(basicResponse.getEncoded());
                        validationResp1.setBasicOCSPResp(basicResponse);
                        validationResp1.setOcspSignerCertHasHasNoCheckExtension(hasIdPkixOcspNoCheckExtension);
                        return validationResp1;
                    }
                    if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
                        LOG.debug("OCSP Result of certificate " + commonNameOfCheckCert + ": UNKNOWN");
                        ValidationResp validationResp1 = new ValidationResp(0, 2, null);
                        validationResp1.setOcspResponseData(basicResponse.getEncoded());
                        validationResp1.setBasicOCSPResp(basicResponse);
                        validationResp1.setOcspSignerCertHasHasNoCheckExtension(hasIdPkixOcspNoCheckExtension);
                        return validationResp1;
                    }
                    LOG.debug("OCSP Result of certificate " + commonNameOfCheckCert + ": GOOD");
                    ValidationResp validationResp = new ValidationResp(0, 0, null);
                    validationResp.setOcspResponseData(basicResponse.getEncoded());
                    validationResp.setBasicOCSPResp(basicResponse);
                    validationResp.setOcspSignerCertHasHasNoCheckExtension(hasIdPkixOcspNoCheckExtension);
                    return validationResp;
                } catch (Exception e) {
                    LOG.error("Error while checking ocsp status. Details: " + Utils.printStackTrace(e));
                    return new ValidationResp(5001);
                }
            LOG.error("Error while checking ocsp status due to no ocsp response");
            return new ValidationResp(5001);
        } catch (Exception e) {
            LOG.error("Error while checking ocsp status. Details: " + Utils.printStackTrace(e));
            return new ValidationResp(5001);
        }
    }

    public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, IOException, OperatorException, CertificateEncodingException {
        CertificateID id = new CertificateID((new JcaDigestCalculatorProviderBuilder()).build().get(CertificateID.HASH_SHA1), (X509CertificateHolder)new JcaX509CertificateHolder(issuerCert), serialNumber);
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(id);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, (ASN1OctetString)new DEROctetString((new DEROctetString(nonce.toByteArray())).getEncoded()));
        gen.setRequestExtensions(new Extensions(new Extension[] { ext }));
        return gen.build();
    }
}

