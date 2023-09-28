package fpt.signature.sign.everification.revocation;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.everification.objects.CrlData;
import fpt.signature.sign.everification.objects.Endpoint;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.lang.NotImplementedException;
import org.apache.log4j.Logger;

public class CrlValidator {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.revocation.CrlValidator.class);

    private static String entityBillCode;

    public CrlValidator(String entityBillCode) {
        fpt.signature.sign.everification.revocation.CrlValidator.entityBillCode = entityBillCode;
    }

    public ValidationResp check(X509Certificate issuerCert, X509Certificate cert) {
        try {
            CRLInnerResult crlInnerResult = getX509CRL(cert);
            X509CRL x509crl = crlInnerResult.getX509CRL();
            if (x509crl == null)
                return new ValidationResp(5001);
            try {
                x509crl.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                e.printStackTrace();
                    LOG.error("Invalid CRL siganture due to invalid CA");
                return new ValidationResp(5001, 3);
            }
            if (x509crl.isRevoked(cert)) {
                    LOG.info("Certificate is revoked!");
                ValidationResp validationResp1 = new ValidationResp(0, 1, x509crl.getRevokedCertificate(cert).getRevocationDate());
                validationResp1.setCrlResponseData(x509crl.getEncoded());
                validationResp1.setX509Crl(x509crl);
                validationResp1.setExpiredCrl(crlInnerResult.isExpiredCrl());
                validationResp1.setCrlEffectiveDt(crlInnerResult.getCrlEffectiveDt());
                return validationResp1;
            }
                LOG.info("Certificate is good!");
            ValidationResp validationResp = new ValidationResp(0, 0, null);
            validationResp.setCrlResponseData(x509crl.getEncoded());
            validationResp.setX509Crl(x509crl);
            validationResp.setExpiredCrl(crlInnerResult.isExpiredCrl());
            validationResp.setCrlEffectiveDt(crlInnerResult.getCrlEffectiveDt());
            return validationResp;
        } catch (Exception e) {
            e.printStackTrace();
            return new ValidationResp(5001);
        }
    }

    private static ValidationResp downloadCrl(X509Certificate x509Certificate) {
        if (Crypto.isRootCACertificate(x509Certificate)) {
                LOG.debug("CA " + x509Certificate.getIssuerDN().toString() + " is ROOTCA. No CRL downloaded");
            return new ValidationResp(5001);
        }
        String issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(x509Certificate);
        CertificationAuthority certificationAuthority = null;
        if (Utils.isNullOrEmpty(issuerKeyIdentifier)) {
            List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
            for (CertificationAuthority ca : listOfCertificationAuthority) {
                if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509Certificate.getIssuerDN().toString())) == 0) {
                    X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                    try {
                        x509Certificate.verify(x509OfCA.getPublicKey());
                        certificationAuthority = ca;
                        break;
                    } catch (Exception exception) {}
                }
            }
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
                for (CertificationAuthority ca : listOfCertificationAuthority) {
                    if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509Certificate.getIssuerDN().toString())) == 0) {
                        X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                        try {
                            x509Certificate.verify(x509OfCA.getPublicKey());
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

                LOG.error("CA " + x509Certificate.getIssuerDN().toString() + " not found. Cannot download CRL");
            return new ValidationResp(5001);
        }
        CAProperties caProperties = certificationAuthority.getCaProperties();
        if (caProperties == null) {
            LOG.error("CAProperties is NULL. Cannot download CRL");
            return new ValidationResp(5001);
        }
        Endpoint endpoint = caProperties.getCrl().getEndpoint();
        if (endpoint.getType().equals("P2P")) {
            LOG.debug("Call CRL using EP_TYPE_P2P");
            if (true) {
                CrlInvocation crlInvocation = new CrlInvocation();
                List<String> crlDists = Crypto.getCRLDistributionPoints(x509Certificate);
                if (Utils.isNullOrEmpty(crlDists.get(0))) {
                        LOG.debug("No CRL URL found in certificate " + x509Certificate.getSubjectDN().toString() + ". This certificate could be RootCA");
                    return new ValidationResp(5001);
                }
                ValidationReq validationReq = new ValidationReq();
                validationReq.setEntityName("VERIFICATION_ENTITY");
                validationReq.setCrlUris(crlDists);
                validationReq.setRetry(caProperties.getCrl().getRetry());
                ValidationResp validationResp = crlInvocation.call(validationReq);
                return validationResp;
            }
                LOG.error("Cannot check ocsp due to Invalid P2P Credentials");
            return new ValidationResp(5001);
        }
        throw new NotImplementedException("Endpoint call hasn't implemented yet");
    }

    public CRLInnerResult getX509CRL(X509Certificate x509Certificate) {
        //DatabaseImpl databaseImpl = new DatabaseImpl();
        X509CRL x509crl = null;
        byte[] crlByte = null;
        String cnOfSubjectDn = CertificatePolicy.getCommonName(x509Certificate.getSubjectDN().toString());
        String cnOfIssuerDn = CertificatePolicy.getCommonName(x509Certificate.getIssuerDN().toString());
        if (Crypto.isCACertificate(x509Certificate) && cnOfIssuerDn.compareTo(cnOfSubjectDn) == 0) {
            LOG.debug("RootCA certificate (self-sign). It doesn't contain CRL distribution");
            return new CRLInnerResult(null, false, null);
        }
        CertificationAuthority certificationAuthority = null;
        String issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(x509Certificate);
        if (Utils.isNullOrEmpty(issuerKeyIdentifier)) {
            List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
            for (CertificationAuthority ca : listOfCertificationAuthority) {
                if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509Certificate.getIssuerDN().toString())) == 0) {
                    X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                    try {
                        x509Certificate.verify(x509OfCA.getPublicKey());
                        certificationAuthority = ca;
                        break;
                    } catch (Exception exception) {}
                }
            }
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
                for (CertificationAuthority ca : listOfCertificationAuthority) {
                    if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509Certificate.getIssuerDN().toString())) == 0) {
                        X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                        try {
                            x509Certificate.verify(x509OfCA.getPublicKey());
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
            LOG.error("CA " + x509Certificate.getIssuerDN().toString() + " not found. Cannot download CRL Data");
            return new CRLInnerResult(null, false, null);
        }
        //CrlData crlData = databaseImpl.getCrlData(certificationAuthority.getCertificationAuthorityID());

        CrlData crlData = null;
        if (crlData == null) {
                LOG.error("Cannot find CRL Data of CA " + x509Certificate.getSubjectDN().toString() + " in system. Try downloading");
            ValidationResp validationResp = downloadCrl(x509Certificate);
            if (validationResp.getResponseCode() == 0) {
                crlByte = validationResp.getCrlResponseData();
                x509crl = Crypto.generateX509CrlObject(crlByte);
//                databaseImpl.updateCrlData(certificationAuthority
//                                .getCertificationAuthorityID(), crlByte, x509crl
//
//                                .getThisUpdate(), x509crl
//                                .getNextUpdate(), x509crl
//                                .getIssuerDN().getName(), null,
//
//                        Configuration.getInstance().getAppUserDBID());
            } else {
                    LOG.error("Cannot download CRL Data of CA " + x509Certificate.getSubjectDN().toString());
                return new CRLInnerResult(null, false, null);
            }
        } else {
            crlByte = crlData.getBlob();
        }
        if (x509crl == null)
            x509crl = Crypto.generateX509CrlObject(crlByte);
        Date nextUpdate = x509crl.getNextUpdate();
        Date currentDate = new Date();
        long diff = Utils.getDifferenceBetweenDatesInMinute(currentDate, nextUpdate);
        if (diff <= 0L) {
                LOG.error("Downloadling CRL Data because of CRL expiration");
            ValidationResp validationResp = downloadCrl(x509Certificate);
            if (validationResp.getResponseCode() == 0) {
                crlByte = validationResp.getCrlResponseData();
                x509crl = Crypto.generateX509CrlObject(crlByte);
//                databaseImpl.updateCrlData(certificationAuthority
//                                .getCertificationAuthorityID(), crlByte, x509crl
//
//                                .getThisUpdate(), x509crl
//                                .getNextUpdate(), x509crl
//                                .getIssuerDN().getName(), null,
//
//                        Configuration.getInstance().getAppUserDBID());
            } else {
                LOG.error("Cannot download CRL Data to update to the latest one. Using the expired one");
            }
        }
        Date now = Calendar.getInstance().getTime();
        boolean expiredCrl = x509crl.getNextUpdate().before(now);
        return new CRLInnerResult(x509crl, expiredCrl, x509crl.getThisUpdate());
    }

    public class CRLInnerResult {
        private X509CRL x509CRL;
        private boolean expiredCrl;
        private Date crlEffectiveDt;

        public CRLInnerResult(X509CRL x509CRL, boolean expiredCrl, Date crlEffectiveDt) {
            this.x509CRL = x509CRL;
            this.expiredCrl = expiredCrl;
            this.crlEffectiveDt = crlEffectiveDt;
        }

        public X509CRL getX509CRL() {
            return this.x509CRL;
        }

        public boolean isExpiredCrl() {
            return this.expiredCrl;
        }

        public Date getCrlEffectiveDt() {
            return this.crlEffectiveDt;
        }

        public void setCrlEffectiveDt(Date crlEffectiveDt) {
            this.crlEffectiveDt = crlEffectiveDt;
        }
    }
}

