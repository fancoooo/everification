package com.itextpdf.signatures;

import com.itextpdf.commons.utils.MessageFormatUtil;
import com.itextpdf.signatures.CRLVerifierEx;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.CertificateVerifier;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.RootStoreVerifier;
import com.itextpdf.signatures.SignUtils;
import com.itextpdf.signatures.VerificationException;
import com.itextpdf.signatures.VerificationOK;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import fpt.signature.sign.everification.objects.X509CRLComparable;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

public class OCSPVerifierEx extends RootStoreVerifier {
    protected static final Logger LOG = Logger.getLogger(com.itextpdf.signatures.OCSPVerifierEx.class);

    protected static final String id_kp_OCSPSigning = "1.3.6.1.5.5.7.3.9";

    protected List<BasicOCSPResp> ocsps;

    public OCSPVerifierEx(CertificateVerifier verifier, List<BasicOCSPResp> ocsps) {
        super(verifier);
        this.ocsps = ocsps;
    }

    public List<VerificationOK> verify(X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        List<VerificationOK> result = new ArrayList<>();
        int validOCSPsFound = 0;
        if (this.ocsps != null)
            for (BasicOCSPResp ocspResp : this.ocsps) {
                if (verify(ocspResp, signCert, issuerCert, signDate))
                    validOCSPsFound++;
            }
        boolean online = false;
        if (this.onlineCheckingAllowed && validOCSPsFound == 0 &&
                verify(getOcspResponse(signCert, issuerCert), signCert, issuerCert, signDate)) {
            validOCSPsFound++;
            online = true;
        }
        LOG.debug("Valid OCSPs found: " + validOCSPsFound);
        if (validOCSPsFound > 0)
            result.add(new VerificationOK(signCert, getClass(), "Valid OCSPs Found: " + validOCSPsFound + (online ? " (online)" : "")));
        if (this.verifier != null)
            result.addAll(this.verifier.verify(signCert, issuerCert, signDate));
        return result;
    }

    public boolean verify(BasicOCSPResp ocspResp, X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        if (ocspResp == null)
            return false;
        SingleResp[] resp = ocspResp.getResponses();
        for (int i = 0; i < resp.length; i++) {
            if (!signCert.getSerialNumber().equals(resp[i].getCertID().getSerialNumber()))
                continue;
            try {
                if (issuerCert == null)
                    issuerCert = signCert;
                if (!SignUtils.checkIfIssuersMatch(resp[i].getCertID(), issuerCert)) {
                    LOG.debug("OCSP: Issuers doesn't match.");
                    continue;
                }
            } catch (IOException e) {
                e.printStackTrace();
                throw new GeneralSecurityException(e.getMessage());
            } catch (OCSPException e) {
                continue;
            }
            if (resp[i].getNextUpdate() == null) {
                Date nextUpdate = SignUtils.add180Sec(resp[i].getThisUpdate());
                LOG.debug(MessageFormatUtil.format("No 'next update' for OCSP Response; assuming {0}", new Object[] { nextUpdate }));
                if (signDate.after(nextUpdate)) {
                    LOG.debug(MessageFormatUtil.format("OCSP no longer valid: {0} after {1}", new Object[] { signDate, nextUpdate }));
                    continue;
                }
            } else if (signDate.after(resp[i].getNextUpdate())) {
                LOG.debug(MessageFormatUtil.format("OCSP no longer valid: {0} after {1}", new Object[] { signDate, resp[i]
                            .getNextUpdate() }));
                continue;
            }
            Object status = resp[i].getCertStatus();
            if (status == CertificateStatus.GOOD) {
                isValidResponse(ocspResp, issuerCert, signDate);
                return true;
            }
            continue;
        }
        return false;
    }

    public boolean verify(BasicOCSPResp ocspResp, List<X509CRL> x509Crls, X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        if (ocspResp == null)
            return false;
        SingleResp[] resp = ocspResp.getResponses();
        for (int i = 0; i < resp.length; i++) {
            if (!signCert.getSerialNumber().equals(resp[i].getCertID().getSerialNumber()))
                continue;
            try {
                if (issuerCert == null)
                    issuerCert = signCert;
                if (!SignUtils.checkIfIssuersMatch(resp[i].getCertID(), issuerCert)) {
                    LOG.debug("OCSP: Issuers doesn't match.");
                    continue;
                }
            } catch (IOException e) {
                e.printStackTrace();
                throw new GeneralSecurityException(e.getMessage());
            } catch (OCSPException e) {
                continue;
            }
            if (resp[i].getNextUpdate() == null) {
                Date nextUpdate = SignUtils.add180Sec(resp[i].getThisUpdate());
                LOG.debug(MessageFormatUtil.format("No 'next update' for OCSP Response; assuming {0}", new Object[] { nextUpdate }));
                if (signDate.after(nextUpdate)) {
                    LOG.debug(MessageFormatUtil.format("OCSP no longer valid: {0} after {1}", new Object[] { signDate, nextUpdate }));
                    continue;
                }
            } else if (signDate.after(resp[i].getNextUpdate())) {
                LOG.debug(MessageFormatUtil.format("OCSP no longer valid: {0} after {1}", new Object[] { signDate, resp[i]
                            .getNextUpdate() }));
                continue;
            }
            Object status = resp[i].getCertStatus();
            if (status == CertificateStatus.GOOD) {
                isValidResponse(ocspResp, x509Crls, issuerCert, signDate);
                return true;
            }
            if (status instanceof RevokedStatus && (
                    (RevokedStatus)status).getRevocationTime().after(signDate)) {
                isValidResponse(ocspResp, x509Crls, issuerCert, signDate);
                return true;
            }
            continue;
        }
        return false;
    }

    public void isValidResponse(BasicOCSPResp ocspResp, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        X509Certificate responderCert = null;
        if (isSignatureValid(ocspResp, issuerCert))
            responderCert = issuerCert;
        if (responderCert == null)
            if (ocspResp.getCerts() != null) {
                Iterable<X509Certificate> certs = SignUtils.getCertsFromOcspResponse(ocspResp);
                for (X509Certificate cert : certs) {
                    List<String> keyPurposes = null;
                    try {
                        keyPurposes = cert.getExtendedKeyUsage();
                        if (keyPurposes != null && keyPurposes.contains("1.3.6.1.5.5.7.3.9") &&
                                isSignatureValid(ocspResp, cert)) {
                            responderCert = cert;
                            break;
                        }
                    } catch (CertificateParsingException certificateParsingException) {}
                }
                if (responderCert == null)
                    throw new VerificationException(issuerCert, "OCSP response could not be verified");
                responderCert.verify(issuerCert.getPublicKey());
                if (responderCert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) == null) {
                    CRL crl;
                    LOG.debug("OCSP signer certificate doesn't have id_pkix_ocsp_nocheck extension.");
                    try {
                        crl = CertificateUtil.getCRL(responderCert);
                    } catch (Exception ignored) {
                        crl = (CRL)null;
                    }
                    if (crl != null && crl instanceof X509CRL) {
                        CRLVerifierEx crlVerifier = new CRLVerifierEx(null, null);
                        crlVerifier.setRootStore(this.rootStore);
                        crlVerifier.setOnlineCheckingAllowed(this.onlineCheckingAllowed);
                        if (!crlVerifier.verify((X509CRL)crl, responderCert, issuerCert, signDate))
                            throw new VerificationException(issuerCert, "Authorized OCSP responder certificate was revoked.");
                    } else {
                        LOG.error("Authorized OCSP responder certificate revocation status cannot be checked");
                    }
                }
            } else {
                if (this.rootStore != null)
                    try {
                        for (X509Certificate anchor : SignUtils.getCertificates(this.rootStore)) {
                            if (isSignatureValid(ocspResp, anchor)) {
                                responderCert = anchor;
                                break;
                            }
                        }
                    } catch (Exception e) {
                        responderCert = (X509Certificate)null;
                    }
                if (responderCert == null)
                    throw new VerificationException(issuerCert, "OCSP response could not be verified: it does not contain certificate chain and response is not signed by issuer certificate or any from the root store.");
            }
    }

    public void isValidResponse(BasicOCSPResp ocspResp, List<X509CRL> x509Crls, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        X509Certificate responderCert = null;
        if (isSignatureValid(ocspResp, issuerCert))
            responderCert = issuerCert;
        if (responderCert == null)
            if (ocspResp.getCerts() != null) {
                Iterable<X509Certificate> certs = SignUtils.getCertsFromOcspResponse(ocspResp);
                for (X509Certificate cert : certs) {
                    List<String> keyPurposes = null;
                    try {
                        keyPurposes = cert.getExtendedKeyUsage();
                        if (keyPurposes != null && keyPurposes.contains("1.3.6.1.5.5.7.3.9") &&
                                isSignatureValid(ocspResp, cert)) {
                            responderCert = cert;
                            break;
                        }
                    } catch (CertificateParsingException certificateParsingException) {}
                }
                if (responderCert == null)
                    throw new VerificationException(issuerCert, "OCSP response could not be verified");
                responderCert.verify(issuerCert.getPublicKey());
                if (responderCert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) == null) {
                    LOG.debug("OCSP signer certificate doesn't have id_pkix_ocsp_nocheck extension.");
                    if (x509Crls == null)
                        throw new VerificationException(issuerCert, "Authorized OCSP responder certificate revocation status cannot be checked due to no /CRLs in /DSS");
                    List<X509CRLComparable> x509CRLComparables = new ArrayList<>();
                    for (X509CRL crl : x509Crls) {
                        CRLVerifierEx crlVerifier = new CRLVerifierEx(null, null);
                        if (crlVerifier.verify(crl, responderCert, issuerCert, signDate))
                            x509CRLComparables.add(new X509CRLComparable(crl, crl.getThisUpdate()));
                    }
                    if (x509CRLComparables.isEmpty())
                        throw new VerificationException(issuerCert, "Authorized OCSP responder certificate revocation status cannot be checked because no CRL data of OCSP signer certificate in /CRLs");
                }
            } else {
                if (this.rootStore != null)
                    try {
                        for (X509Certificate anchor : SignUtils.getCertificates(this.rootStore)) {
                            if (isSignatureValid(ocspResp, anchor)) {
                                responderCert = anchor;
                                break;
                            }
                        }
                    } catch (Exception e) {
                        responderCert = (X509Certificate)null;
                    }
                if (responderCert == null)
                    throw new VerificationException(issuerCert, "OCSP response could not be verified: it does not contain certificate chain and response is not signed by issuer certificate or any from the root store.");
            }
    }

    public boolean isSignatureValid(BasicOCSPResp ocspResp, Certificate responderCert) {
        try {
            return SignUtils.isSignatureValid(ocspResp, responderCert, "BC");
        } catch (Exception e) {
            return false;
        }
    }

    public BasicOCSPResp getOcspResponse(X509Certificate signCert, X509Certificate issuerCert) {
        if (signCert == null && issuerCert == null)
            return null;
        OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle(null);
        BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp(signCert, issuerCert, null);
        if (ocspResp == null)
            return null;
        SingleResp[] resps = ocspResp.getResponses();
        for (SingleResp resp : resps) {
            Object status = resp.getCertStatus();
            if (status == CertificateStatus.GOOD)
                return ocspResp;
        }
        return null;
    }
}

