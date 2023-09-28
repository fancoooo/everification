package fpt.signature.sign.everification.core;


import java.security.cert.X509Certificate;
import java.util.List;

import fpt.signature.sign.everification.objects.Result;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.core.CertPathValidation;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;

public class TrustedCertificateChecks {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.TrustedCertificateChecks.class);

    public Result validate(List<X509Certificate> chain) {
        List<X509Certificate> newChain = chain;
        if (newChain == null) {

                LOG.error("Signature has no chain --> Trusted Certificate Checks result false");
            return new Result(false, chain);
        }
        X509Certificate x509 = newChain.get(0);
        if (Crypto.isRootCACertificate(x509)) {
            String subjectKeyIdentitider = Crypto.getSubjectKeyIdentifier(x509);
            if (Utils.isNullOrEmpty(subjectKeyIdentitider)) {
                List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
                boolean foundTrustedCA = false;
                for (CertificationAuthority ca : listOfCertificationAuthority) {
                    if (ca.getCommonName().compareTo(CertificatePolicy.getCommonName(x509.getIssuerDN().toString())) == 0) {
                        X509Certificate x509OfCA = Crypto.getX509Object(ca.getPemCertificate());
                        try {
                            x509.verify(x509OfCA.getPublicKey());
                            foundTrustedCA = true;
                            break;
                        } catch (Exception exception) {}
                    }
                }
                if (foundTrustedCA)
                    return new Result(true, chain);
                return new Result(false, chain);
            }
            CertificationAuthority certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(subjectKeyIdentitider);
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(subjectKeyIdentitider);
                if (certificationAuthority == null)
                    return new Result(false, chain);
                return new Result(true, chain);
            }
            return new Result(true, chain);
        }
        newChain = (new CertPathValidation()).buildPath(x509);
        if (newChain.size() == 1) {
            newChain = (new CertPathValidation()).buildPathBaseOnIssuerName(x509);
            if (newChain.size() == 1) {

                    LOG.error("Cannot build chain for certificate signer " + CertificatePolicy.getCommonName(x509.getSubjectDN().toString()) + " --> Un-Trusted certificate");
                return new Result(false, chain);
            }
        }
        X509Certificate mayItRootCA = newChain.get(newChain.size() - 1);
        if (!Crypto.isRootCACertificate(mayItRootCA)) {

                LOG.error("Cannot find/add Root CA --> Trusted Certificate Checks result false");
            return new Result(false, chain);
        }
        return new Result(true, newChain);
    }
}

