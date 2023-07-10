package fpt.signature.sign.ocsp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.Proxy.Type;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;

import fpt.signature.sign.core.X509CertificateInfo;
import fpt.signature.sign.ex.ConnectErrorException;
import fpt.signature.sign.ex.InvalidCerException;
import fpt.signature.sign.ex.NotFoundURL;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;

public class OCSPConnection implements IOCSPConnection {
    private static final Logger LOG = Logger.getLogger(OCSPConnection.class);
    private static final String QUERY_THROUGH_PROXY_SERVER = "QUERY_THROUGH_PROXY_SERVER";
    private static final String PROXY_IP = "PROXY_IP";
    private static final String PROXY_PORT = "PROXY_PORT";
    private static final String PROXY_USER = "PROXY_USER";
    private static final String PROXY_PASSWORD = "PROXY_PASSWORD";
    public static final int CONNECTION_TIMEOUT = 300;

    public OCSPConnection() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public OCSPCertStatus checkCerOCSP(String cer) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        return this.checkCerOCSP((String)cer, (String)null, (Date)null);
    }

    public OCSPCertStatus checkCerOCSP(String cer, String ocspUrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        if (cert == null) {
            LOG.error("Base64 Certificate of user input incorrect.");
            throw new InvalidCerException(new Date() + ":Base64 Certificate of user input incorrect");
        } else {
            X509CertificateInfo cerInfo = new X509CertificateInfo(cert);
            if (null != ocspUrl) {
                LOG.error("Use custom ocsp responder at " + ocspUrl);
                cerInfo.setUrlOcsp(ocspUrl);
            }

            X509Certificate issuer = Utils.getIssuerCert(cert);
            if (issuer == null) {
                LOG.error("No issuer certificate found.");
                return OCSPCertStatus.UNKNOWN;
            } else {
                OCSPCertStatus certStatus = OCSPCertStatus.UNKNOWN;

                try {
                    CertificateID id = new CertificateID("1.3.14.3.2.26", issuer, cert.getSerialNumber());
                    OCSPReqGenerator gen = new OCSPReqGenerator();
                    gen.addRequest(id);
                    OCSPReq ocspReq = gen.generate();
                    OCSPResp ocspResp = this.queryOcspResponse(ocspReq, cerInfo, cert, issuer);
                    OCSPResponseCode respStatus = OCSPResponseCode.UNKNOWN;
                    if (ocspResp == null) {
                        throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                    } else {
                        switch(ocspResp.getStatus()) {
                            case 0:
                                respStatus = OCSPResponseCode.SUCCESSFUL;
                                break;
                            case 1:
                                respStatus = OCSPResponseCode.MALFORMED_REQUEST;
                                break;
                            case 2:
                                respStatus = OCSPResponseCode.INTERNAL_ERROR;
                                break;
                            case 3:
                                respStatus = OCSPResponseCode.TRY_LATER;
                                break;
                            case 4:
                            default:
                                respStatus = OCSPResponseCode.UNKNOWN;
                                break;
                            case 5:
                                respStatus = OCSPResponseCode.SIG_REQUIRED;
                                break;
                            case 6:
                                respStatus = OCSPResponseCode.UNAUTHORIZED;
                        }

                        if (respStatus != OCSPResponseCode.SUCCESSFUL) {
                            throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                        } else {
                            BasicOCSPResp basicResp = (BasicOCSPResp)ocspResp.getResponseObject();
                            SingleResp certResponse = basicResp.getResponses()[0];
                            Object status = certResponse.getCertStatus();
                            certStatus = OCSPCertStatus.UNKNOWN;
                            if (status == null) {
                                certStatus = OCSPCertStatus.GOOD;
                            } else if (status instanceof RevokedStatus) {
                                certStatus = OCSPCertStatus.REVOKED;
                                if (dateTime != null) {
                                    RevokedStatus revStatus = (RevokedStatus)status;
                                    Date revocationTime = revStatus.getRevocationTime();
                                    revStatus.getRevocationReason();
                                    if (dateTime.before(revocationTime)) {
                                        certStatus = OCSPCertStatus.GOOD;
                                    }
                                }
                            }

                            return certStatus;
                        }
                    }
                } catch (OCSPException var18) {
                    java.util.logging.Logger.getLogger(OCSPConnection.class.getName()).log(Level.SEVERE, (String)null, var18);
                    return certStatus;
                }
            }
        }
    }

    public OCSPCertStatus checkCerOCSP(X509Certificate cert, String ocspUrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        System.out.println("Checking for ocsp status...");
        if (cert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of user input incorrect");
        } else {
            X509CertificateInfo cerInfo = new X509CertificateInfo(cert);
            if (null != ocspUrl) {
                cerInfo.setUrlOcsp(ocspUrl);
            }

            X509Certificate issuer = Utils.getIssuerCert(cert);
            if (issuer == null) {
                System.out.println("Not found issuer certificate");
                return OCSPCertStatus.UNKNOWN;
            } else {
                System.out.println("found issuer certificate");
                OCSPCertStatus certStatus = OCSPCertStatus.UNKNOWN;

                try {
                    CertificateID id = new CertificateID("1.3.14.3.2.26", issuer, cert.getSerialNumber());
                    OCSPReqGenerator gen = new OCSPReqGenerator();
                    gen.addRequest(id);
                    OCSPReq ocspReq = gen.generate();
                    OCSPResp ocspResp = this.queryOcspResponse(ocspReq, cerInfo, cert, issuer);
                    OCSPResponseCode respStatus = OCSPResponseCode.UNKNOWN;
                    if (ocspResp == null) {
                        throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                    } else {
                        switch(ocspResp.getStatus()) {
                            case 0:
                                respStatus = OCSPResponseCode.SUCCESSFUL;
                                break;
                            case 1:
                                respStatus = OCSPResponseCode.MALFORMED_REQUEST;
                                break;
                            case 2:
                                respStatus = OCSPResponseCode.INTERNAL_ERROR;
                                break;
                            case 3:
                                respStatus = OCSPResponseCode.TRY_LATER;
                                break;
                            case 4:
                            default:
                                respStatus = OCSPResponseCode.UNKNOWN;
                                break;
                            case 5:
                                respStatus = OCSPResponseCode.SIG_REQUIRED;
                                break;
                            case 6:
                                respStatus = OCSPResponseCode.UNAUTHORIZED;
                        }

                        if (respStatus != OCSPResponseCode.SUCCESSFUL) {
                            throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                        } else {
                            BasicOCSPResp basicResp = (BasicOCSPResp)ocspResp.getResponseObject();
                            SingleResp certResponse = basicResp.getResponses()[0];
                            Object status = certResponse.getCertStatus();
                            certStatus = OCSPCertStatus.UNKNOWN;
                            if (status == null) {
                                certStatus = OCSPCertStatus.GOOD;
                            } else if (status instanceof RevokedStatus) {
                                certStatus = OCSPCertStatus.REVOKED;
                                if (dateTime != null) {
                                    RevokedStatus revStatus = (RevokedStatus)status;
                                    Date revocationTime = revStatus.getRevocationTime();
                                    revStatus.getRevocationReason();
                                    if (dateTime.before(revocationTime)) {
                                        certStatus = OCSPCertStatus.GOOD;
                                    }
                                }
                            }

                            return certStatus;
                        }
                    }
                } catch (Exception var17) {
                    java.util.logging.Logger.getLogger(OCSPConnection.class.getName()).log(Level.SEVERE, (String)null, var17);
                    return certStatus;
                }
            }
        }
    }

    public OCSPCertStatus checkCerOCSP(ArrayList<X509Certificate> certChain, String ocspUrl, Date dateTime) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        X509Certificate cert = (X509Certificate)certChain.get(0);
        System.out.println("checkCerOCSP start");
        if (cert == null) {
            throw new InvalidCerException(new Date() + ":Base64 Certificate of user input incorrect");
        } else {
            X509CertificateInfo cerInfo = new X509CertificateInfo(cert);
            if (null != ocspUrl) {
                cerInfo.setUrlOcsp(ocspUrl);
            }

            X509Certificate issuer = (X509Certificate)certChain.get(1);
            OCSPCertStatus certStatus = OCSPCertStatus.UNKNOWN;

            try {
                CertificateID id = new CertificateID("1.3.14.3.2.26", issuer, cert.getSerialNumber());
                OCSPReqGenerator gen = new OCSPReqGenerator();
                gen.addRequest(id);
                OCSPReq ocspReq = gen.generate();
                OCSPResp ocspResp = this.queryOcspResponse(ocspReq, cerInfo, cert, issuer);
                OCSPResponseCode respStatus = OCSPResponseCode.UNKNOWN;
                if (ocspResp == null) {
                    throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                } else {
                    switch(ocspResp.getStatus()) {
                        case 0:
                            respStatus = OCSPResponseCode.SUCCESSFUL;
                            break;
                        case 1:
                            respStatus = OCSPResponseCode.MALFORMED_REQUEST;
                            break;
                        case 2:
                            respStatus = OCSPResponseCode.INTERNAL_ERROR;
                            break;
                        case 3:
                            respStatus = OCSPResponseCode.TRY_LATER;
                            break;
                        case 4:
                        default:
                            respStatus = OCSPResponseCode.UNKNOWN;
                            break;
                        case 5:
                            respStatus = OCSPResponseCode.SIG_REQUIRED;
                            break;
                        case 6:
                            respStatus = OCSPResponseCode.UNAUTHORIZED;
                    }

                    if (respStatus != OCSPResponseCode.SUCCESSFUL) {
                        throw new OCSPException(new Date() + ":OCSP server returned status: " + respStatus);
                    } else {
                        BasicOCSPResp basicResp = (BasicOCSPResp)ocspResp.getResponseObject();
                        SingleResp certResponse = basicResp.getResponses()[0];
                        Object status = certResponse.getCertStatus();
                        certStatus = OCSPCertStatus.UNKNOWN;
                        if (status == null) {
                            certStatus = OCSPCertStatus.GOOD;
                        } else if (status instanceof RevokedStatus) {
                            certStatus = OCSPCertStatus.REVOKED;
                            if (dateTime != null) {
                                RevokedStatus revStatus = (RevokedStatus)status;
                                Date revocationTime = revStatus.getRevocationTime();
                                revStatus.getRevocationReason();
                                if (dateTime.before(revocationTime)) {
                                    certStatus = OCSPCertStatus.GOOD;
                                }
                            }
                        }

                        return certStatus;
                    }
                }
            } catch (OCSPException var18) {
                java.util.logging.Logger.getLogger(OCSPConnection.class.getName()).log(Level.SEVERE, "OCSPException: " + var18.getMessage());
                System.out.println("checkCerOCSP " + var18.getMessage());
                return certStatus;
            }
        }
    }

    public OCSPCertStatus checkCerOCSP(String cer, Date dateTime) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.checkCerOCSP((String)cer, (String)null, dateTime);
    }

    private OCSPResp queryOcspResponse(OCSPReq ocspReq, X509CertificateInfo cerInfo, X509Certificate cert, X509Certificate issuer) {
        if (cerInfo != null && cerInfo.getUrlOcsp() != null) {
            if (!cerInfo.getUrlOcsp().startsWith("http")) {
                System.out.println("Only http protocol is supported for ocsp url.");
                return null;
            } else {
                LOG.info(cerInfo.getUrlOcsp());

                byte[] requestData;
                try {
                    requestData = ocspReq.getEncoded();
                } catch (IOException var22) {
                    System.out.println("No ocsp request data."+ var22.getMessage());
                    return null;
                }

                boolean useProxy = false;
                String proxyIp = null;
                String proxyUser = null;
                String proxyPass = null;
                int proxyPort = -1;

                String confUseProxy;
                try {
                    confUseProxy = System.getenv("QUERY_THROUGH_PROXY_SERVER");
                    if ("TRUE".equalsIgnoreCase(confUseProxy)) {
                        useProxy = true;
                        proxyIp = System.getenv("PROXY_IP");
                        proxyUser = System.getenv("PROXY_USER");
                        proxyPass = System.getenv("PROXY_PASSWORD");
                        proxyPort = Integer.parseInt(System.getenv("PROXY_PORT"));
                    }
                } catch (Exception var21) {
                    LOG.error("Cannot read PROXY envirollment variables: " + var21.getMessage());
                }

                confUseProxy = null;

                URL url;
                try {
                    url = new URL(cerInfo.getUrlOcsp());
                } catch (MalformedURLException var20) {
                    LOG.error("Ocsp url is malformed: " + var20.getMessage());
                    return null;
                }

                HttpURLConnection con = null;
                if (useProxy) {
                    LOG.info("Query ocsp through proxy at " + proxyIp + ":" + proxyPort);
                    if (proxyUser != null && !"".equals(proxyUser) && proxyUser != null && !"".equals(proxyPass)) {
                        final String proxyU = proxyUser;
                        final String proxyP = proxyPass;
                        Authenticator authenticator = new Authenticator() {
                            public PasswordAuthentication getPasswordAuthentication() {

                                return new PasswordAuthentication(proxyU, proxyP.toCharArray());
                            }
                        };
                        Authenticator.setDefault(authenticator);
                    }

                    try {
                        Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress(proxyIp, proxyPort));
                        con = (HttpURLConnection)url.openConnection(proxy);
                    } catch (Exception var19) {
                        LOG.error("Cannot create url connection: " + var19.getMessage());
                    }
                } else {
                    LOG.info("Query ocsp without proxy");

                    try {
                        con = (HttpURLConnection)url.openConnection();
                    } catch (Exception var18) {
                        LOG.error("Cannot create url connection: " + var18.getMessage());
                    }
                }

                if (con == null) {
                    return null;
                } else {
                    con.setRequestProperty("Content-Type", "application/ocsp-request");
                    con.setRequestProperty("Accept", "application/ocsp-response");
                    con.setRequestProperty("Content-Length", String.valueOf(requestData.length));
                    con.setDoOutput(true);
                    con.setAllowUserInteraction(false);
                    con.setUseCaches(false);
                    con.setConnectTimeout(300);

                    try {
                        OutputStream dataStream = con.getOutputStream();
                        dataStream.write(requestData);
                        dataStream.close();
                        if (con.getResponseCode() != 200) {
                            throw new ConnectErrorException(new Date() + "Request to OCSP URL did not return valid response code: " + con.getResponseCode() + ". Check URL OCSP Server again!");
                        }

                        return new OCSPResp(con.getInputStream());
                    } catch (IOException var16) {
                        LOG.error("IOException: " + var16.getMessage());
                    } catch (ConnectErrorException var17) {
                        LOG.error("ConnectErrorException: " + var17.getMessage());
                    }

                    return null;
                }
            }
        } else {
            LOG.error("No signer certificate information for ocsp");
            return null;
        }
    }
}
