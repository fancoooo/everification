package fpt.signature.sign.everification.core;


import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.everification.objects.RevocationChecks;
import fpt.signature.sign.everification.revocation.CrlValidator;
import fpt.signature.sign.everification.revocation.OcspValidator;
import fpt.signature.sign.everification.revocation.ValidationResp;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Configuration;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;

public class RevocationStatusChecks {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.RevocationStatusChecks.class);

    private final String lang;

    private final String entityBillCode;

    private final int acceptableCrlDuration;

    private Boolean forceToCheckCrl = null;

    private Boolean forceToCheckOcsp = null;

    private Boolean trueSigningTime = null;

    public RevocationStatusChecks(String lang, String entityBillCode, Boolean forceToCheckOcsp, Boolean forceToCheckCrl, Boolean trueSigningTime, int acceptableCrlDuration) {
        this.lang = lang;
        this.entityBillCode = entityBillCode;
        this.forceToCheckOcsp = forceToCheckOcsp;
        this.forceToCheckCrl = forceToCheckCrl;
        this.acceptableCrlDuration = acceptableCrlDuration;
        this.trueSigningTime = trueSigningTime;
    }

    public RevocationChecks validate(X509Certificate x509, Date signingTime) {
        RevocationChecks revocationResult = new RevocationChecks();
        String issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(x509);
        CertificationAuthority certificationAuthority = null;
        if (Utils.isNullOrEmpty(issuerKeyIdentifier)) {

            LOG.warn("issuerKeyIdentifier of certificate " + CertificatePolicy.getCommonName(x509.getSubjectDN().toString() + " is NULL"));
            List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
            for (CertificationAuthority ca : listOfCertificationAuthority) {
                if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509.getIssuerDN().toString())) == 0) {
                    X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                    try {
                        x509.verify(x509OfCA.getPublicKey());
                        certificationAuthority = ca;
                        break;
                    } catch (Exception exception) {}
                }
            }
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
                for (CertificationAuthority ca : listOfCertificationAuthority) {
                    if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509.getIssuerDN().toString())) == 0) {
                        X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                        try {
                            x509.verify(x509OfCA.getPublicKey());
                            certificationAuthority = ca;
                            break;
                        } catch (Exception exception) {}
                    }
                }
            }
        } else {
            certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            }
        }
        if (certificationAuthority == null) {
            LOG.error("Cannot find CA with issuerKeyIdentifier: " + issuerKeyIdentifier);
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("NONE");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(0)));
            return revocationResult;
        }
        boolean crlEnabled = false;
        boolean ocspEnabled = false;
        if (this.forceToCheckCrl == null || this.forceToCheckOcsp == null) {
            CAProperties caProperties = certificationAuthority.getCaProperties();
            if (caProperties == null) {
                LOG.error("CAProperties is NULL. CA name: " + certificationAuthority.getName());
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("NONE");
                revocationResult.setStatus("FAILED");
                revocationResult.setStatusAtPresent("FAILED");
                revocationResult.setDescription(getDescription(String.valueOf(1)));
                return revocationResult;
            }
            crlEnabled = caProperties.isCrlEnabled();
            ocspEnabled = caProperties.isOcspEnabled();
        } else {
            crlEnabled = this.forceToCheckCrl;
            ocspEnabled = this.forceToCheckOcsp;
        }
        X509Certificate issuerCert = Crypto.getX509Object(certificationAuthority.getPemCertificate());
        if (!crlEnabled && !ocspEnabled) {
            LOG.info("No check revocation status");
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("NONE");
            revocationResult.setStatus("NONE");
            revocationResult.setStatusAtPresent("NONE");
            revocationResult.setDescription(getDescription(String.valueOf(2)));
            return revocationResult;
        }
        if (crlEnabled && ocspEnabled) {
            LOG.info("Certificate revocation against both CRL/OCSP");
            OcspValidator ocspValidator = new OcspValidator(this.entityBillCode);
            ValidationResp ocspResp = ocspValidator.check(issuerCert, x509);
            if (ocspResp.getResponseCode() == 0) {
                if (ocspResp.getRevocationStatus() == 1) {
                    if (signingTime != null) {
                        if (ocspResp.getRevocationDt().before(signingTime)) {
                                if (this.trueSigningTime.booleanValue()) {
                                    LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                } else {
                                    LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                }
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("OCSP");
                            revocationResult.setStatus("REVOKED");
                            revocationResult.setStatusAtPresent("REVOKED");
                            revocationResult.setDescription(getDescription(String.valueOf(5)));
                            revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                            revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                            revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                            revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                            return revocationResult;
                        }

                            LOG.debug("Revocation time after signing time --> GOOD");
                        revocationResult.setSuccess(true);
                        revocationResult.setProtocol("OCSP");
                        revocationResult.setStatus("GOOD");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(6)));
                        revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                        revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                        revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                        revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                        return revocationResult;
                    }
                        LOG.debug("Signing time is NULL --> REVOKED");
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(9)));
                    revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                if (ocspResp.getRevocationStatus() == 0) {
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("GOOD");
                    revocationResult.setDescription(getDescription(String.valueOf(7)));
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                if (ocspResp.getRevocationStatus() == 2) {
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("UNKNOWN");
                    revocationResult.setStatusAtPresent("UNKNOWN");
                    revocationResult.setDescription(getDescription(String.valueOf(8)));
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("OCSP");
                revocationResult.setStatus("FAILED");
                revocationResult.setStatusAtPresent("FAILED");
                revocationResult.setDescription(getDescription(String.valueOf(3)));
                revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                return revocationResult;
            }
            CrlValidator crlValidator1 = new CrlValidator(this.entityBillCode);
            ValidationResp validationResp1 = crlValidator1.check(issuerCert, x509);
            if (validationResp1.getResponseCode() == 0) {
                if (!Crypto.isCACertificate(x509) && this.trueSigningTime
                        .booleanValue()) {
                    if (x509.getNotAfter().after(validationResp1.getCrlEffectiveDt()) || x509
                            .getNotAfter().equals(validationResp1.getCrlEffectiveDt())) {
                        if (this.trueSigningTime.booleanValue()) {
                            if (signingTime != null) {
                                if (signingTime.before(validationResp1.getCrlEffectiveDt()) || signingTime
                                        .equals(validationResp1.getCrlEffectiveDt())) {
                                    if (validationResp1.getRevocationStatus() == 1) {
                                        if (signingTime != null) {
                                            if (validationResp1.getRevocationDt().before(signingTime)) {
                                                    if (this.trueSigningTime.booleanValue()) {
                                                        LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                                    } else {
                                                        LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                                    }
                                                revocationResult.setSuccess(false);
                                                revocationResult.setProtocol("CRL");
                                                revocationResult.setStatus("REVOKED");
                                                revocationResult.setStatusAtPresent("REVOKED");
                                                revocationResult.setDescription(getDescription(String.valueOf(5)));
                                                revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                                                revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                                revocationResult.setX509Crl(validationResp1.getX509Crl());
                                                return revocationResult;
                                            }

                                                LOG.debug("Revocation time after signing time --> GOOD");
                                            revocationResult.setSuccess(true);
                                            revocationResult.setProtocol("CRL");
                                            revocationResult.setStatus("GOOD");
                                            revocationResult.setStatusAtPresent("REVOKED");
                                            revocationResult.setDescription(getDescription(String.valueOf(6)));
                                            revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                                            revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                            revocationResult.setX509Crl(validationResp1.getX509Crl());
                                            return revocationResult;
                                        }

                                            LOG.debug("Signing time is NULL --> REVOKED");
                                        revocationResult.setSuccess(false);
                                        revocationResult.setProtocol("CRL");
                                        revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                                        revocationResult.setStatusAtPresent("REVOKED");
                                        revocationResult.setDescription(getDescription(String.valueOf(9)));
                                        revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                                        return revocationResult;
                                    }
                                    if (validationResp1.getRevocationStatus() == 0) {
                                        revocationResult.setSuccess(true);
                                        revocationResult.setProtocol("CRL");
                                        revocationResult.setStatus("GOOD");
                                        revocationResult.setStatusAtPresent("GOOD");
                                        revocationResult.setDescription(getDescription(String.valueOf(7)));
                                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                                        return revocationResult;
                                    }
                                    if (validationResp1.getRevocationStatus() == 2) {
                                        revocationResult.setSuccess(false);
                                        revocationResult.setProtocol("CRL");
                                        revocationResult.setStatus("UNKNOWN");
                                        revocationResult.setStatusAtPresent("UNKNOWN");
                                        revocationResult.setDescription(getDescription(String.valueOf(8)));
                                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                                        return revocationResult;
                                    }
                                    revocationResult.setSuccess(false);
                                    revocationResult.setProtocol("CRL");
                                    revocationResult.setStatus("FAILED");
                                    revocationResult.setStatusAtPresent("FAILED");
                                    revocationResult.setDescription(getDescription(String.valueOf(3)));
                                    revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                    revocationResult.setX509Crl(validationResp1.getX509Crl());
                                    return revocationResult;
                                }

                                    LOG.debug("Hasn't conclude the revocation status of this certificate yet because SigningTime > EffectiveDate of CRL");
                                revocationResult.setSuccess(false);
                                revocationResult.setProtocol("CRL");
                                revocationResult.setStatus("NONE");
                                revocationResult.setStatusAtPresent("NONE");
                                revocationResult.setDescription(getDescription(String.valueOf(11)));
                                return revocationResult;
                            }

                                LOG.debug("Cannot check the revocation status because the SigningTime is NULL or EMPTY");
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("CRL");
                            revocationResult.setStatus("FAILED");
                            revocationResult.setStatusAtPresent("FAILED");
                            revocationResult.setDescription(getDescription(String.valueOf(4)));
                            return revocationResult;
                        }

                            LOG.debug("Cannot check the revocation status of certificate " + x509.getSubjectDN().toString() + " because the SigningTime is NULL or SigningTime is NOW()");
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("FAILED");
                        revocationResult.setStatusAtPresent("FAILED");
                        revocationResult.setDescription(getDescription(String.valueOf(4)));
                        return revocationResult;
                    }
                    if (validationResp1.getRevocationStatus() == 1) {
                        if (signingTime != null) {
                            if (validationResp1.getRevocationDt().before(signingTime)) {

                                    if (this.trueSigningTime.booleanValue()) {
                                        LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                    } else {
                                        LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                    }
                                revocationResult.setSuccess(false);
                                revocationResult.setProtocol("CRL");
                                revocationResult.setStatus("REVOKED");
                                revocationResult.setStatusAtPresent("REVOKED");
                                revocationResult.setDescription(getDescription(String.valueOf(5)));
                                revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                                revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                                revocationResult.setX509Crl(validationResp1.getX509Crl());
                                return revocationResult;
                            }

                                LOG.debug("Revocation time after signing time --> GOOD");
                            revocationResult.setSuccess(true);
                            revocationResult.setProtocol("CRL");
                            revocationResult.setStatus("GOOD");
                            revocationResult.setStatusAtPresent("REVOKED");
                            revocationResult.setDescription(getDescription(String.valueOf(6)));
                            revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                            revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                            revocationResult.setX509Crl(validationResp1.getX509Crl());
                            return revocationResult;
                        }

                            LOG.debug("Signing time is NULL --> REVOKED");
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(9)));
                        revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                        return revocationResult;
                    }
                    if (validationResp1.getRevocationStatus() == 0) {
                        revocationResult.setSuccess(true);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("GOOD");
                        revocationResult.setStatusAtPresent("GOOD");
                        revocationResult.setDescription(getDescription(String.valueOf(7)));
                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                        return revocationResult;
                    }
                    if (validationResp1.getRevocationStatus() == 2) {
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("UNKNOWN");
                        revocationResult.setStatusAtPresent("UNKNOWN");
                        revocationResult.setDescription(getDescription(String.valueOf(8)));
                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                        return revocationResult;
                    }
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("FAILED");
                    revocationResult.setStatusAtPresent("FAILED");
                    revocationResult.setDescription(getDescription(String.valueOf(3)));
                    revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                    revocationResult.setX509Crl(validationResp1.getX509Crl());
                    return revocationResult;
                }
                if (validationResp1.getRevocationStatus() == 1) {
                    if (signingTime != null) {
                        if (validationResp1.getRevocationDt().before(signingTime)) {

                                if (this.trueSigningTime.booleanValue()) {
                                    LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                } else {
                                    LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                }
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("CRL");
                            revocationResult.setStatus("REVOKED");
                            revocationResult.setStatusAtPresent("REVOKED");
                            revocationResult.setDescription(getDescription(String.valueOf(5)));
                            revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                            revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                            revocationResult.setX509Crl(validationResp1.getX509Crl());
                            return revocationResult;
                        }

                            LOG.debug("Revocation time after signing time --> GOOD");
                        revocationResult.setSuccess(true);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("GOOD");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(6)));
                        revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                        revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                        revocationResult.setX509Crl(validationResp1.getX509Crl());
                        return revocationResult;
                    }

                        LOG.debug("Signing time is NULL --> REVOKED");
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(9)));
                    revocationResult.setRevocationDt(validationResp1.getRevocationDt());
                    revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                    revocationResult.setX509Crl(validationResp1.getX509Crl());
                    return revocationResult;
                }
                if (validationResp1.getRevocationStatus() == 0) {
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("GOOD");
                    revocationResult.setDescription(getDescription(String.valueOf(7)));
                    revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                    revocationResult.setX509Crl(validationResp1.getX509Crl());
                    return revocationResult;
                }
                if (validationResp1.getRevocationStatus() == 2) {
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("UNKNOWN");
                    revocationResult.setStatusAtPresent("UNKNOWN");
                    revocationResult.setDescription(getDescription(String.valueOf(8)));
                    revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                    revocationResult.setX509Crl(validationResp1.getX509Crl());
                    return revocationResult;
                }
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("FAILED");
                revocationResult.setStatusAtPresent("FAILED");
                revocationResult.setDescription(getDescription(String.valueOf(3)));
                revocationResult.setCrlResponseData(validationResp1.getCrlResponseData());
                revocationResult.setX509Crl(validationResp1.getX509Crl());
                return revocationResult;
            }
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("CRL");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(4)));
            return revocationResult;
        }
        if (ocspEnabled) {
            OcspValidator ocspValidator = new OcspValidator(this.entityBillCode);
            ValidationResp ocspResp = ocspValidator.check(issuerCert, x509);
            if (ocspResp.getResponseCode() == 0) {
                if (ocspResp.getRevocationStatus() == 1) {
                    if (signingTime != null) {
                        if (ocspResp.getRevocationDt().before(signingTime)) {

                                if (this.trueSigningTime.booleanValue()) {
                                    LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                } else {
                                    LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                }
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("OCSP");
                            revocationResult.setStatus("REVOKED");
                            revocationResult.setStatusAtPresent("REVOKED");
                            revocationResult.setDescription(getDescription(String.valueOf(5)));
                            revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                            revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                            revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                            revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                            return revocationResult;
                        }

                            LOG.debug("Revocation time after signing time --> GOOD");
                        revocationResult.setSuccess(true);
                        revocationResult.setProtocol("OCSP");
                        revocationResult.setStatus("GOOD");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(6)));
                        revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                        revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                        revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                        revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                        return revocationResult;
                    }

                        LOG.debug("Signing time is NULL --> REVOKED");
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(9)));
                    revocationResult.setRevocationDt(ocspResp.getRevocationDt());
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                if (ocspResp.getRevocationStatus() == 0) {
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("GOOD");
                    revocationResult.setDescription(getDescription(String.valueOf(7)));
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                if (ocspResp.getRevocationStatus() == 2) {
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("UNKNOWN");
                    revocationResult.setStatusAtPresent("UNKNOWN");
                    revocationResult.setDescription(getDescription(String.valueOf(8)));
                    revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                    revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                    revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                    return revocationResult;
                }
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("OCSP");
                revocationResult.setStatus("FAILED");
                revocationResult.setStatusAtPresent("FAILED");
                revocationResult.setDescription(getDescription(String.valueOf(3)));
                revocationResult.setOcspResponseData(ocspResp.getOcspResponseData());
                revocationResult.setBasicOCSPResp(ocspResp.getBasicOCSPResp());
                revocationResult.setOcspSignerCertHasNoCheckExtension(ocspResp.isOcspSignerCertHasHasNoCheckExtension());
                return revocationResult;
            }
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("OCSP");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(4)));
            return revocationResult;
        }
        CrlValidator crlValidator = new CrlValidator(this.entityBillCode);
        ValidationResp crlResp = crlValidator.check(issuerCert, x509);
        if (crlResp.getResponseCode() == 0) {
            if (!Crypto.isCACertificate(x509) && this.trueSigningTime
                    .booleanValue()) {
                if (x509.getNotAfter().after(crlResp.getCrlEffectiveDt()) || x509
                        .getNotAfter().equals(crlResp.getCrlEffectiveDt())) {
                    if (this.trueSigningTime.booleanValue()) {
                        if (signingTime != null) {
                            if (signingTime.before(crlResp.getCrlEffectiveDt()) || signingTime
                                    .equals(crlResp.getCrlEffectiveDt())) {
                                if (crlResp.getRevocationStatus() == 1) {
                                    if (signingTime != null) {
                                        if (crlResp.getRevocationDt().before(signingTime)) {

                                                if (this.trueSigningTime.booleanValue()) {
                                                    LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                                } else {
                                                    LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                                }
                                            revocationResult.setSuccess(false);
                                            revocationResult.setProtocol("CRL");
                                            revocationResult.setStatus("REVOKED");
                                            revocationResult.setStatusAtPresent("REVOKED");
                                            revocationResult.setDescription(getDescription(String.valueOf(5)));
                                            revocationResult.setRevocationDt(crlResp.getRevocationDt());
                                            revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                            revocationResult.setX509Crl(crlResp.getX509Crl());
                                            return revocationResult;
                                        }

                                            LOG.debug("Revocation time after signing time --> GOOD");
                                        revocationResult.setSuccess(true);
                                        revocationResult.setProtocol("CRL");
                                        revocationResult.setStatus("GOOD");
                                        revocationResult.setStatusAtPresent("REVOKED");
                                        revocationResult.setDescription(getDescription(String.valueOf(6)));
                                        revocationResult.setRevocationDt(crlResp.getRevocationDt());
                                        revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                        revocationResult.setX509Crl(crlResp.getX509Crl());
                                        return revocationResult;
                                    }

                                        LOG.debug("Signing time is NULL --> REVOKED");
                                    revocationResult.setSuccess(false);
                                    revocationResult.setProtocol("CRL");
                                    revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                                    revocationResult.setStatusAtPresent("REVOKED");
                                    revocationResult.setDescription(getDescription(String.valueOf(9)));
                                    revocationResult.setRevocationDt(crlResp.getRevocationDt());
                                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                    revocationResult.setX509Crl(crlResp.getX509Crl());
                                    return revocationResult;
                                }
                                if (crlResp.getRevocationStatus() == 0) {
                                    revocationResult.setSuccess(true);
                                    revocationResult.setProtocol("CRL");
                                    revocationResult.setStatus("GOOD");
                                    revocationResult.setStatusAtPresent("GOOD");
                                    revocationResult.setDescription(getDescription(String.valueOf(7)));
                                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                    revocationResult.setX509Crl(crlResp.getX509Crl());
                                    return revocationResult;
                                }
                                if (crlResp.getRevocationStatus() == 2) {
                                    revocationResult.setSuccess(false);
                                    revocationResult.setProtocol("CRL");
                                    revocationResult.setStatus("UNKNOWN");
                                    revocationResult.setStatusAtPresent("UNKNOWN");
                                    revocationResult.setDescription(getDescription(String.valueOf(8)));
                                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                    revocationResult.setX509Crl(crlResp.getX509Crl());
                                    return revocationResult;
                                }
                                revocationResult.setSuccess(false);
                                revocationResult.setProtocol("CRL");
                                revocationResult.setStatus("FAILED");
                                revocationResult.setStatusAtPresent("FAILED");
                                revocationResult.setDescription(getDescription(String.valueOf(3)));
                                revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                                revocationResult.setX509Crl(crlResp.getX509Crl());
                                return revocationResult;
                            }

                                LOG.debug("Hasn't conclude the revocation status of this certificate yet because SigningTime > EffectiveDate of CRL");
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("CRL");
                            revocationResult.setStatus("NONE");
                            revocationResult.setStatusAtPresent("NONE");
                            revocationResult.setDescription(getDescription(String.valueOf(11)));
                            return revocationResult;
                        }

                            LOG.debug("Cannot check the revocation status because the SigningTime is NULL or EMPTY");
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("FAILED");
                        revocationResult.setStatusAtPresent("FAILED");
                        revocationResult.setDescription(getDescription(String.valueOf(4)));
                        return revocationResult;
                    }

                        LOG.debug("Cannot check the revocation status of certificate " + x509.getSubjectDN().toString() + " because the SigningTime is NULL or SigningTime is NOW()");
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("FAILED");
                    revocationResult.setStatusAtPresent("FAILED");
                    revocationResult.setDescription(getDescription(String.valueOf(4)));
                    return revocationResult;
                }
                if (crlResp.getRevocationStatus() == 1) {
                    if (signingTime != null) {
                        if (crlResp.getRevocationDt().before(signingTime)) {

                                if (this.trueSigningTime.booleanValue()) {
                                    LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                } else {
                                    LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                                }
                            revocationResult.setSuccess(false);
                            revocationResult.setProtocol("CRL");
                            revocationResult.setStatus("REVOKED");
                            revocationResult.setStatusAtPresent("REVOKED");
                            revocationResult.setDescription(getDescription(String.valueOf(5)));
                            revocationResult.setRevocationDt(crlResp.getRevocationDt());
                            revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                            revocationResult.setX509Crl(crlResp.getX509Crl());
                            return revocationResult;
                        }

                            LOG.debug("Revocation time after signing time --> GOOD");
                        revocationResult.setSuccess(true);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("GOOD");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(6)));
                        revocationResult.setRevocationDt(crlResp.getRevocationDt());
                        revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                        revocationResult.setX509Crl(crlResp.getX509Crl());
                        return revocationResult;
                    }

                        LOG.debug("Signing time is NULL --> REVOKED");
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(9)));
                    revocationResult.setRevocationDt(crlResp.getRevocationDt());
                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                    revocationResult.setX509Crl(crlResp.getX509Crl());
                    return revocationResult;
                }
                if (crlResp.getRevocationStatus() == 0) {
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("GOOD");
                    revocationResult.setDescription(getDescription(String.valueOf(7)));
                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                    revocationResult.setX509Crl(crlResp.getX509Crl());
                    return revocationResult;
                }
                if (crlResp.getRevocationStatus() == 2) {
                    revocationResult.setSuccess(false);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("UNKNOWN");
                    revocationResult.setStatusAtPresent("UNKNOWN");
                    revocationResult.setDescription(getDescription(String.valueOf(8)));
                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                    revocationResult.setX509Crl(crlResp.getX509Crl());
                    return revocationResult;
                }
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("FAILED");
                revocationResult.setStatusAtPresent("FAILED");
                revocationResult.setDescription(getDescription(String.valueOf(3)));
                revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                revocationResult.setX509Crl(crlResp.getX509Crl());
                return revocationResult;
            }
            if (crlResp.getRevocationStatus() == 1) {
                if (signingTime != null) {
                    if (crlResp.getRevocationDt().before(signingTime)) {

                            if (this.trueSigningTime.booleanValue()) {
                                LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            } else {
                                LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            }
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("REVOKED");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(5)));
                        revocationResult.setRevocationDt(crlResp.getRevocationDt());
                        revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                        revocationResult.setX509Crl(crlResp.getX509Crl());
                        return revocationResult;
                    }

                        LOG.debug("Revocation time after signing time --> GOOD");
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(6)));
                    revocationResult.setRevocationDt(crlResp.getRevocationDt());
                    revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                    revocationResult.setX509Crl(crlResp.getX509Crl());
                    return revocationResult;
                }
                    LOG.debug("Signing time is NULL --> REVOKED");
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                revocationResult.setStatusAtPresent("REVOKED");
                revocationResult.setDescription(getDescription(String.valueOf(9)));
                revocationResult.setRevocationDt(crlResp.getRevocationDt());
                revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                revocationResult.setX509Crl(crlResp.getX509Crl());
                return revocationResult;
            }
            if (crlResp.getRevocationStatus() == 0) {
                revocationResult.setSuccess(true);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("GOOD");
                revocationResult.setStatusAtPresent("GOOD");
                revocationResult.setDescription(getDescription(String.valueOf(7)));
                revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                revocationResult.setX509Crl(crlResp.getX509Crl());
                return revocationResult;
            }
            if (crlResp.getRevocationStatus() == 2) {
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("UNKNOWN");
                revocationResult.setStatusAtPresent("UNKNOWN");
                revocationResult.setDescription(getDescription(String.valueOf(8)));
                revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
                revocationResult.setX509Crl(crlResp.getX509Crl());
                return revocationResult;
            }
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("CRL");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(3)));
            revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
            revocationResult.setX509Crl(crlResp.getX509Crl());
            return revocationResult;
        }
        revocationResult.setSuccess(false);
        revocationResult.setProtocol("CRL");
        revocationResult.setStatus("FAILED");
        revocationResult.setStatusAtPresent("FAILED");
        revocationResult.setDescription(getDescription(String.valueOf(4)));
        revocationResult.setCrlResponseData(crlResp.getCrlResponseData());
        revocationResult.setX509Crl(crlResp.getX509Crl());
        return revocationResult;
    }

    public RevocationChecks validate(X509Certificate x509, Date signingTime, BasicOCSPResp basicOCSPResp) {
        RevocationChecks revocationResult = new RevocationChecks();
        try {
            SingleResp[] responses = basicOCSPResp.getResponses();
            SingleResp resp = responses[0];
            Object status = resp.getCertStatus();
            int revocationStatus = 0;
            if (status instanceof RevokedStatus) {
                revocationStatus = 1;
            } else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
                revocationStatus = 2;
            } else {
                revocationStatus = 0;
            }
            if (revocationStatus == 1) {
                if (signingTime != null) {
                    if (((RevokedStatus)status).getRevocationTime().before(signingTime)) {

                            if (this.trueSigningTime.booleanValue()) {
                                LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            } else {
                                LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            }
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("OCSP");
                        revocationResult.setStatus("REVOKED");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(5)));
                        revocationResult.setRevocationDt(((RevokedStatus)status).getRevocationTime());
                        revocationResult.setOcspResponseData(basicOCSPResp.getEncoded());
                        revocationResult.setBasicOCSPResp(basicOCSPResp);
                        revocationResult.setOcspSignerCertHasNoCheckExtension(Crypto.hasIdPkixOcspNoCheckExtension(Crypto.getOcspSigner(basicOCSPResp)));
                        return revocationResult;
                    }

                        LOG.debug("Revocation time after signing time --> GOOD");
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("OCSP");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(6)));
                    revocationResult.setRevocationDt(((RevokedStatus)status).getRevocationTime());
                    revocationResult.setOcspResponseData(basicOCSPResp.getEncoded());
                    revocationResult.setBasicOCSPResp(basicOCSPResp);
                    revocationResult.setOcspSignerCertHasNoCheckExtension(Crypto.hasIdPkixOcspNoCheckExtension(Crypto.getOcspSigner(basicOCSPResp)));
                    return revocationResult;
                }

                    LOG.debug("Signing time is NULL --> REVOKED");
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("OCSP");
                revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                revocationResult.setStatusAtPresent("REVOKED");
                revocationResult.setDescription(getDescription(String.valueOf(9)));
                revocationResult.setRevocationDt(((RevokedStatus)status).getRevocationTime());
                revocationResult.setOcspResponseData(basicOCSPResp.getEncoded());
                revocationResult.setBasicOCSPResp(basicOCSPResp);
                revocationResult.setOcspSignerCertHasNoCheckExtension(Crypto.hasIdPkixOcspNoCheckExtension(Crypto.getOcspSigner(basicOCSPResp)));
                return revocationResult;
            }
            if (revocationStatus == 0) {
                revocationResult.setSuccess(true);
                revocationResult.setProtocol("OCSP");
                revocationResult.setStatus("GOOD");
                revocationResult.setStatusAtPresent("GOOD");
                revocationResult.setDescription(getDescription(String.valueOf(7)));
                revocationResult.setOcspResponseData(basicOCSPResp.getEncoded());
                revocationResult.setBasicOCSPResp(basicOCSPResp);
                revocationResult.setOcspSignerCertHasNoCheckExtension(Crypto.hasIdPkixOcspNoCheckExtension(Crypto.getOcspSigner(basicOCSPResp)));
                return revocationResult;
            }
            if (revocationStatus == 2) {
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("OCSP");
                revocationResult.setStatus("UNKNOWN");
                revocationResult.setStatusAtPresent("UNKNOWN");
                revocationResult.setDescription(getDescription(String.valueOf(8)));
                revocationResult.setOcspResponseData(basicOCSPResp.getEncoded());
                revocationResult.setBasicOCSPResp(basicOCSPResp);
                revocationResult.setOcspSignerCertHasNoCheckExtension(Crypto.hasIdPkixOcspNoCheckExtension(Crypto.getOcspSigner(basicOCSPResp)));
                return revocationResult;
            }
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("OCSP");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(3)));
            revocationResult.setOcspResponseData(null);
            revocationResult.setBasicOCSPResp(null);
            revocationResult.setOcspSignerCertHasNoCheckExtension(false);
            return revocationResult;
        } catch (Exception e) {
            e.printStackTrace();
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("OCSP");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(4)));
            revocationResult.setOcspResponseData(null);
            revocationResult.setBasicOCSPResp(null);
            revocationResult.setOcspSignerCertHasNoCheckExtension(false);
            return revocationResult;
        }
    }

    public RevocationChecks validate(X509Certificate x509, Date signingTime, X509CRL crl) {
        RevocationChecks revocationResult = new RevocationChecks();
        try {
            int revocationStatus = 0;
            if (crl.isRevoked(x509)) {
                revocationStatus = 1;
            } else {
                revocationStatus = 0;
            }
            if (revocationStatus == 1) {
                if (signingTime != null) {
                    if (crl.getRevokedCertificate(x509).getRevocationDate().before(signingTime)) {

                            if (this.trueSigningTime.booleanValue()) {
                                LOG.debug("Revocation time before signing time (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            } else {
                                LOG.debug("Revocation time before Now (" + signingTime + ") --> REVOKED (" + x509.getSubjectDN().toString() + ")");
                            }
                        revocationResult.setSuccess(false);
                        revocationResult.setProtocol("CRL");
                        revocationResult.setStatus("REVOKED");
                        revocationResult.setStatusAtPresent("REVOKED");
                        revocationResult.setDescription(getDescription(String.valueOf(5)));
                        revocationResult.setRevocationDt(crl.getRevokedCertificate(x509).getRevocationDate());
                        revocationResult.setCrlResponseData(crl.getEncoded());
                        revocationResult.setX509Crl(crl);
                        return revocationResult;
                    }

                        LOG.debug("Revocation time after signing time --> GOOD");
                    revocationResult.setSuccess(true);
                    revocationResult.setProtocol("CRL");
                    revocationResult.setStatus("GOOD");
                    revocationResult.setStatusAtPresent("REVOKED");
                    revocationResult.setDescription(getDescription(String.valueOf(6)));
                    revocationResult.setRevocationDt(crl.getRevokedCertificate(x509).getRevocationDate());
                    revocationResult.setCrlResponseData(crl.getEncoded());
                    revocationResult.setX509Crl(crl);
                    return revocationResult;
                }

                    LOG.debug("Signing time is NULL --> REVOKED");
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("REVOKED_NO_SIGNING_TIME_CHECK");
                revocationResult.setStatusAtPresent("REVOKED");
                revocationResult.setDescription(getDescription(String.valueOf(9)));
                revocationResult.setRevocationDt(crl.getRevokedCertificate(x509).getRevocationDate());
                revocationResult.setCrlResponseData(crl.getEncoded());
                revocationResult.setX509Crl(crl);
                return revocationResult;
            }
            if (revocationStatus == 0) {
                revocationResult.setSuccess(true);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("GOOD");
                revocationResult.setStatusAtPresent("GOOD");
                revocationResult.setDescription(getDescription(String.valueOf(7)));
                revocationResult.setCrlResponseData(crl.getEncoded());
                revocationResult.setX509Crl(crl);
                return revocationResult;
            }
            if (revocationStatus == 2) {
                revocationResult.setSuccess(false);
                revocationResult.setProtocol("CRL");
                revocationResult.setStatus("UNKNOWN");
                revocationResult.setStatusAtPresent("UNKNOWN");
                revocationResult.setDescription(getDescription(String.valueOf(8)));
                revocationResult.setCrlResponseData(crl.getEncoded());
                revocationResult.setX509Crl(crl);
                return revocationResult;
            }
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("CRL");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(3)));
            revocationResult.setCrlResponseData(crl.getEncoded());
            revocationResult.setX509Crl(crl);
            return revocationResult;
        } catch (Exception e) {
            e.printStackTrace();
            revocationResult.setSuccess(false);
            revocationResult.setProtocol("CRL");
            revocationResult.setStatus("FAILED");
            revocationResult.setStatusAtPresent("FAILED");
            revocationResult.setDescription(getDescription(String.valueOf(4)));
            revocationResult.setCrlResponseData(null);
            revocationResult.setX509Crl(null);
            return revocationResult;
        }
    }

    public String getDescription(String code) {
        String key = "revocation." + this.lang + "." + code;
        return Configuration.getInstance().getVerificationDescription().getProperty(key);
    }
}

