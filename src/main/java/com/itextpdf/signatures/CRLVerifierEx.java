package com.itextpdf.signatures;

import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.CertificateVerifier;
import com.itextpdf.signatures.RootStoreVerifier;
import com.itextpdf.signatures.SignUtils;
import com.itextpdf.signatures.TimestampConstants;
import com.itextpdf.signatures.VerificationException;
import com.itextpdf.signatures.VerificationOK;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;

public class CRLVerifierEx extends RootStoreVerifier {
    protected static final Logger LOG = Logger.getLogger(com.itextpdf.signatures.CRLVerifierEx.class);

    List<X509CRL> crls;

    public CRLVerifierEx(CertificateVerifier verifier, List<X509CRL> crls) {
        super(verifier);
        this.crls = crls;
    }

    public List<VerificationOK> verify(X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        List<VerificationOK> result = new ArrayList<>();
        int validCrlsFound = 0;
        if (this.crls != null)
            for (X509CRL crl : this.crls) {
                if (verify(crl, signCert, issuerCert, signDate))
                    validCrlsFound++;
            }
        boolean online = false;
        if (this.onlineCheckingAllowed && validCrlsFound == 0 &&
                verify(getCRL(signCert, issuerCert), signCert, issuerCert, signDate)) {
            validCrlsFound++;
            online = true;
        }
        LOG.debug("Valid CRLs found: " + validCrlsFound);
        if (validCrlsFound > 0)
            result.add(new VerificationOK(signCert, getClass(), "Valid CRLs found: " + validCrlsFound + (online ? " (online)" : "")));
        if (this.verifier != null)
            result.addAll(this.verifier.verify(signCert, issuerCert, signDate));
        return result;
    }

    public boolean verify(X509CRL crl, X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException {
        if (crl == null || signDate == TimestampConstants.UNDEFINED_TIMESTAMP_DATE)
            return false;
        if (crl.getIssuerX500Principal().equals(signCert.getIssuerX500Principal()) && signDate
                .before(crl.getNextUpdate())) {
            if (isSignatureValid(crl, issuerCert) && crl.isRevoked(signCert) && crl
                    .getRevokedCertificate(signCert).getRevocationDate().before(signDate))
                throw new VerificationException(signCert, "The certificate has been revoked.");
            return true;
        }
        return false;
    }

    public X509CRL getCRL(X509Certificate signCert, X509Certificate issuerCert) {
        if (issuerCert == null)
            issuerCert = signCert;
        try {
            String crlurl = CertificateUtil.getCRLURL(signCert);
            if (crlurl == null)
                return null;
            LOG.debug("Getting CRL from " + crlurl);
            return (X509CRL)SignUtils.parseCrlFromStream((new URL(crlurl)).openStream());
        } catch (IOException|GeneralSecurityException e) {
            return null;
        }
    }

    public boolean isSignatureValid(X509CRL crl, X509Certificate crlIssuer) {
        if (crlIssuer != null)
            try {
                crl.verify(crlIssuer.getPublicKey());
                return true;
            } catch (GeneralSecurityException e) {
                LOG.warn("CRL not issued by the same authority as the certificate that is being checked");
            }
        if (this.rootStore == null)
            return false;
        try {
            for (X509Certificate anchor : SignUtils.getCertificates(this.rootStore)) {
                try {
                    crl.verify(anchor.getPublicKey());
                    return true;
                } catch (GeneralSecurityException generalSecurityException) {}
            }
        } catch (GeneralSecurityException generalSecurityException) {}
        return false;
    }
}

