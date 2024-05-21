package fpt.signature.sign.crl;

import fpt.signature.sign.core.X509CertificateInfo;
import fpt.signature.sign.ex.*;
import fpt.signature.sign.utils.Utils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

public class CRLConnection implements ICRLConnection {

    public CRLCertStatus checkCerCRL(String cer) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        return this.checkCerCRL((String)cer, (String)null, (Date)null);
    }

    public CRLCertStatus checkCerCRL(String cer, String crlUrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        return this.checkCerCRL(cert, crlUrl, dateTime);
    }

    public CRLCertStatus checkCerCRL(X509Certificate cert, String crlUrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        if (cert == null) {
            throw new InvalidCerException("Cerificate format error");
        } else {
            X509Certificate issuer = Utils.getIssuerCert(cert);
            if (issuer == null) {
                throw new InvalidCerException("Not found issuer certificate");
            } else {
                ArrayList<X509Certificate> certChain = new ArrayList();
                certChain.add(cert);
                certChain.add(issuer);
                return this.checkCerCRL(certChain, crlUrl, dateTime);
            }
        }
    }

    public CRLCertStatus checkCerCRLFromFile(String cer, String crlFile, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        if (cert == null) {
            throw new InvalidCerException("Chung thu khong dung dinh dang");
        } else {
            X509CertificateInfo certInfo = new X509CertificateInfo(cert);
            X509Certificate issuer = certInfo.getIssuer();

            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                FileInputStream fis = new FileInputStream(crlFile);
                X509CRL crl = null;
                crl = (X509CRL)cf.generateCRL(fis);
                crl.verify(issuer.getPublicKey());
                if (!crl.isRevoked(cert)) {
                    return CRLCertStatus.UNREVOKED;
                } else {
                    if (dateTime != null) {
                        Set s = crl.getRevokedCertificates();
                        if (s != null && !s.isEmpty()) {
                            Iterator t = s.iterator();

                            while(t.hasNext()) {
                                X509CRLEntry entry = (X509CRLEntry)t.next();
                                if (cert.getSerialNumber().compareTo(entry.getSerialNumber()) == 0 && dateTime.before(entry.getRevocationDate())) {
                                    return CRLCertStatus.UNREVOKED;
                                }
                            }
                        }
                    }

                    return CRLCertStatus.REVOKED;
                }
            } catch (Exception var13) {
                throw new ConnectErrorException("Connection fail!");
            }
        }
    }

    public CRLCertStatus checkCerCRLFromURL(String cer, String issuserCer, String url) throws InvalidBase64Input, InvalidCerException, ConnectErrorException {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        X509Certificate issuerCert = Utils.StringToX509Certificate(issuserCer);
        if (cert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of user input incorrect");
        } else if (issuerCert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of Issuer input incorrect");
        } else {
            System.setProperty("com.sun.security.enableCRLDP", "true");
            CertificateFactory cf = null;
            X509CRL crl = null;

            try {
                cf = CertificateFactory.getInstance("X509");
                InputStream inStream = X509CertificateInfo.queryUrlConnection(url);
                if (inStream == null) {
                    throw new ConnectErrorException("Connect to URL of CRL Store Error, check connection again");
                } else {
                    crl = (X509CRL)cf.generateCRL(inStream);
                    crl.verify(issuerCert.getPublicKey());
                    inStream.close();
                    return crl.isRevoked(cert) ? CRLCertStatus.REVOKED : CRLCertStatus.UNREVOKED;
                }
            } catch (Exception var9) {
                throw new ConnectErrorException();
            }
        }
    }

    public CRLCertStatus checkCerCRLFromFile(String cer, String issuserCer, String pathFile) throws InvalidBase64Input, InvalidCerException, NotFoundOrInvalidFormatCRLFile {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        X509Certificate issuerCert = Utils.StringToX509Certificate(issuserCer);
        if (cert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of user input incorrect");
        } else if (issuerCert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of Issuer input incorrect");
        } else {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                FileInputStream fis = new FileInputStream(pathFile);
                X509CRL crl = null;
                crl = (X509CRL)cf.generateCRL(fis);
                crl.verify(issuerCert.getPublicKey());
                return crl.isRevoked(cert) ? CRLCertStatus.REVOKED : CRLCertStatus.UNREVOKED;
            } catch (Exception var9) {
                throw new NotFoundOrInvalidFormatCRLFile();
            }
        }
    }

    public CRLCertStatus checkCerCRL(ArrayList<X509Certificate> certChain, String urlCrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        if (certChain == null) {
            throw new InvalidCerException("Chung thu khong dung dinh dang");
        } else {
            X509Certificate cert = (X509Certificate)certChain.get(0);
            X509Certificate issuer = (X509Certificate)certChain.get(1);
            CRLCertStatus status = CRLCertStatus.UNKOWN;
            X509CertificateInfo certInfo = new X509CertificateInfo(cert);
            if (null != urlCrl) {
                certInfo.setUrlCrl(urlCrl);
            }

            X509CRL crl = certInfo.getCrl();

            try {
                crl.verify(issuer.getPublicKey());
                if (crl.isRevoked(cert)) {
                    if (dateTime != null) {
                        Set s = crl.getRevokedCertificates();
                        if (s != null && !s.isEmpty()) {
                            Iterator t = s.iterator();

                            while(t.hasNext()) {
                                X509CRLEntry entry = (X509CRLEntry)t.next();
                                if (cert.getSerialNumber().compareTo(entry.getSerialNumber()) == 0 && dateTime.before(entry.getRevocationDate())) {
                                    status = CRLCertStatus.UNREVOKED;
                                }
                            }
                        }
                    }

                    status = CRLCertStatus.REVOKED;
                } else {
                    status = CRLCertStatus.UNREVOKED;
                }

                return status;
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | CRLException var12) {
                throw new ConnectErrorException("Connection fail!. " + var12.getMessage());
            }
        }
    }
}
