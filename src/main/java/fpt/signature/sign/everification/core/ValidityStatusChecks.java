package fpt.signature.sign.everification.core;


import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.objects.ValidityChecks;
import fpt.signature.sign.utils.Configuration;

public class ValidityStatusChecks {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.ValidityStatusChecks.class);

    private final String lang;

    public ValidityStatusChecks(String lang) {
        this.lang = lang;
    }

    public ValidityChecks validate(X509Certificate x509, Date signingTime) {
        int validSigningTimeAndCertificateDuration = 3;
        int validCertificateDuration = 1;
        if (signingTime != null) {
            try {
                x509.checkValidity(signingTime);
                validSigningTimeAndCertificateDuration = 0;
            } catch (CertificateExpiredException ex) {
                LOG.error("SigningTime is not valid due to certificate is already expired");
                validSigningTimeAndCertificateDuration = 1;
            } catch (CertificateNotYetValidException ex) {
                LOG.error("SigningTime is not valid due to certificate is not valid yet");
                validSigningTimeAndCertificateDuration = 2;
            }
        } else {
            validSigningTimeAndCertificateDuration = 3;
        }
        try {
            x509.checkValidity(Calendar.getInstance().getTime());
            validCertificateDuration = 0;
        } catch (CertificateExpiredException ex) {
            LOG.error("Certificate is not valid due to certificate is already expired");
            validCertificateDuration = 1;
        } catch (CertificateNotYetValidException ex) {
            LOG.error("Certificate is not valid due to certificate is not valid yet");
            validCertificateDuration = 2;
        }
        ValidityChecks validityChecks = new ValidityChecks();
        String description = "";
        boolean finalResult = false;
        boolean signingTimeValid = false;
        switch (validSigningTimeAndCertificateDuration) {
            case 0:
                signingTimeValid = true;
                validityChecks.setStatus("CERT_VALID_AT_SIGN_TIME");
                description = description + getValidityDescription(String.valueOf(0));
                break;
            case 1:
                validityChecks.setStatus("CERT_EXPIRED_AT_SIGN_TIME");
                description = description + getValidityDescription(String.valueOf(1));
                break;
            case 2:
                validityChecks.setStatus("CERT_NOT_YET_VALID_AT_SIGN_TIME");
                description = description + getValidityDescription(String.valueOf(2));
                break;
            default:
                validityChecks.setStatus("VALIDITY_NO_SIGNING_TIME_CHECK");
                description = description + getValidityDescription(String.valueOf(8));
                break;
        }
        switch (validCertificateDuration) {
            case 0:
                validityChecks.setStatusAtPresent("CERT_VALID_AT_CHECK_TIME");
                description = description + " - " + getValidityDescription(String.valueOf(3));
                break;
            case 1:
                validityChecks.setStatusAtPresent("CERT_EXPIRED_AT_CHECK_TIME");
                description = description + " - " + getValidityDescription(String.valueOf(4));
                break;
            default:
                validityChecks.setStatusAtPresent("CERT_NOT_YET_VALID_AT_CHECK_TIME");
                description = description + " - " + getValidityDescription(String.valueOf(5));
                break;
        }
        boolean signAuthorityKu = false;
        boolean signAuthorityEKU = false;
        boolean signAuthority = false;
        boolean[] keyUsages = x509.getKeyUsage();
        List<String> extendedKeyUsages = null;
        try {
            extendedKeyUsages = x509.getExtendedKeyUsage();
        } catch (CertificateParsingException certificateParsingException) {}
        if (keyUsages == null) {
            signAuthorityKu = false;
        } else if (keyUsages[0]) {
            signAuthorityKu = true;
        } else {
            signAuthorityKu = false;
        }
        if (extendedKeyUsages == null) {
            signAuthorityEKU = false;
        } else {
            for (String eku : extendedKeyUsages) {
                if (eku.trim().compareToIgnoreCase("1.3.6.1.4.1.311.10.3.12") == 0 || eku
                        .trim().compareToIgnoreCase("1.2.840.113583.1.1.5") == 0 || eku
                        .trim().compareToIgnoreCase("1.3.6.1.5.5.7.3.8") == 0) {
                    signAuthorityEKU = true;
                    break;
                }
            }
        }
        signAuthority = (signAuthorityKu || signAuthorityEKU);
        if (signAuthority) {
            description = description + " - " + getValidityDescription(String.valueOf(6));
        } else {
            description = description + " - " + getValidityDescription(String.valueOf(7));
        }
        finalResult = (signAuthority && signingTimeValid);
        validityChecks.setSignPurpose(signAuthority);
        validityChecks.setDescription(description);
        validityChecks.setSuccess(finalResult);
        return validityChecks;
    }

    public String getValidityDescription(String code) {
        String key = "validity." + this.lang + "." + code;
        return Configuration.getInstance().getVerificationDescription().getProperty(key);
    }

    public static boolean isExpired(X509Certificate x509) {
        try {
            x509.checkValidity(Calendar.getInstance().getTime());
            return false;
        } catch (CertificateExpiredException ex) {
            return true;
        } catch (CertificateNotYetValidException ex) {
            return false;
        }
    }

    public static boolean isNotValidYet(X509Certificate x509) {
        try {
            x509.checkValidity(Calendar.getInstance().getTime());
            return false;
        } catch (CertificateExpiredException ex) {
            return false;
        } catch (CertificateNotYetValidException ex) {
            return true;
        }
    }
}

