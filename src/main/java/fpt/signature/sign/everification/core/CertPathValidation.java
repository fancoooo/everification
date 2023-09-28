package fpt.signature.sign.everification.core;


import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import fpt.signature.sign.general.Resources;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;


public class CertPathValidation {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.CertPathValidation.class);

    public List<X509Certificate> buildPath(X509Certificate x509) {
        List<X509Certificate> certPath = new ArrayList<>();
        String issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(x509);
        String subjectKeyIdentitider = Crypto.getSubjectKeyIdentifier(x509);
        certPath.add(x509);
        while (!Utils.isNullOrEmpty(issuerKeyIdentifier) && issuerKeyIdentifier
                .compareToIgnoreCase(subjectKeyIdentitider) != 0) {
            CertificationAuthority certificationAuthority = (CertificationAuthority) Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            if (certificationAuthority == null) {
                Resources.reloadCertificationAuthorities();
                certificationAuthority = (CertificationAuthority)Resources.getCertificationAuthoritiesKeyIdentifiers().get(issuerKeyIdentifier);
            }
            if (certificationAuthority == null)
                return certPath;
            X509Certificate issuer = Crypto.getX509Object(certificationAuthority.getPemCertificate());
            issuerKeyIdentifier = Crypto.getIssuerKeyIdentifier(issuer);
            subjectKeyIdentitider = Crypto.getSubjectKeyIdentifier(issuer);
            certPath.add(issuer);
        }
        return certPath;
    }

    public List<X509Certificate> buildPathBaseOnIssuerName(X509Certificate x509) {

            LOG.debug("Building path based on issuer's common name");
        List<X509Certificate> certPath = new ArrayList<>();
        certPath.add(x509);
        String issuerCommonName = CertificatePolicy.getCommonName(x509.getIssuerDN().toString());
        String subjectCommonName = CertificatePolicy.getCommonName(x509.getSubjectDN().toString());
        if (issuerCommonName.compareTo(subjectCommonName) == 0)
            return certPath;
        List<CertificationAuthority> listOfCertificationAuthority = Resources.getListOfCertificationAuthority();
        for (CertificationAuthority caLv1 : listOfCertificationAuthority) {
            if (caLv1.getCommonName().compareTo(issuerCommonName) == 0 &&
                    Crypto.hasRelationship(x509, caLv1.getX509Object())) {
                certPath.add(caLv1.getX509Object());

                    LOG.debug("Add Root/Sub CA " + caLv1.getCommonName());
                issuerCommonName = CertificatePolicy.getCommonName(caLv1.getX509Object().getIssuerDN().toString());
                subjectCommonName = CertificatePolicy.getCommonName(caLv1.getX509Object().getSubjectDN().toString());
                if (issuerCommonName.compareTo(subjectCommonName) == 0)
                    return certPath;
                for (CertificationAuthority caLv2 : listOfCertificationAuthority) {
                    if (caLv2.getCommonName().compareTo(issuerCommonName) == 0 &&
                            Crypto.hasRelationship(caLv1.getX509Object(), caLv2.getX509Object())) {
                        certPath.add(caLv2.getX509Object());

                            LOG.debug("Add Root/Sub CA " + caLv2.getCommonName());
                        issuerCommonName = CertificatePolicy.getCommonName(caLv2.getX509Object().getIssuerDN().toString());
                        subjectCommonName = CertificatePolicy.getCommonName(caLv2.getX509Object().getSubjectDN().toString());
                        if (issuerCommonName.compareTo(subjectCommonName) == 0)
                            return certPath;
                        for (CertificationAuthority caLv3 : listOfCertificationAuthority) {
                            if (caLv3.getCommonName().compareTo(issuerCommonName) == 0 &&
                                    Crypto.hasRelationship(caLv2.getX509Object(), caLv3.getX509Object())) {
                                certPath.add(caLv3.getX509Object());

                                    LOG.debug("Add Root/Sub CA " + caLv3.getCommonName());
                                return certPath;
                            }
                        }
                    }
                }
            }
        }

            LOG.error("This certificate (" + x509.getIssuerDN().toString() + ") maybe issued by un-trusted CAs because it cannot be built cert path");
        return certPath;
    }

    public boolean validate(List<X509Certificate> chain) {
        if (chain == null) {

                LOG.error("Signature has no chain --> Cert Path Validation result false");
            return false;
        }
        if (chain.size() == 1) {

                LOG.error("Signature has only siging certificate. Signer: " + CertificatePolicy.getCommonName(((X509Certificate)chain.get(0)).getSubjectDN().toString()));
            return true;
        }
        for (int i = 0; i < chain.size(); i++) {
            int firstIndex = i;
            int secondIndex = i + 1;
            if (secondIndex >= chain.size())
                return true;
            if (!validate(chain.get(firstIndex), chain.get(secondIndex)))
                return false;
        }
        return true;
    }

    private boolean validate(X509Certificate cert1, X509Certificate cert2) {
        boolean rs = false;
        if (cert2 != null) {
            try {
                cert1.verify(cert2.getPublicKey());
                rs = true;
            } catch (Exception e) {
                rs = false;
            }
        } else {
            rs = true;
        }

            LOG.debug("Checking Certificate CertPath\n\tCERT1: " + cert1.getSubjectDN().toString() + "\n\tCERT2: " + cert2
                    .getSubjectDN().toString() + "--> " + rs);
        return rs;
    }
}

