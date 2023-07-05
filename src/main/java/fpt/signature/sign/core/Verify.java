package fpt.signature.sign.core;

import fpt.signature.sign.crl.CRLCertStatus;
import fpt.signature.sign.crl.CRLConnection;
import fpt.signature.sign.crl.ICRLConnection;
import fpt.signature.sign.ex.*;
import fpt.signature.sign.object.EnKeyUsage;
import fpt.signature.sign.object.EnhancedKeyUsage;
import fpt.signature.sign.ocsp.IOCSPConnection;
import fpt.signature.sign.ocsp.OCSPCertStatus;
import fpt.signature.sign.ocsp.OCSPConnection;
import fpt.signature.sign.utils.Utils;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Verify {
    private ICRLConnection crlConnection = new CRLConnection();
    private IOCSPConnection ocspConnection = new OCSPConnection();
    private final String ROOT_CA = "MIIDbDCCAtWgAwIBAgIIBVFAeZ5Ph/kwDQYJKoZIhvcNAQEFBQAwZjE4MDYGA1UEAwwvVk5QVCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBUZWNobm9sb2d5IERlbW8gQ0ExHTAbBgNVBAsMFFZOUFQtQ0EgVHJ1c3QgTmV0d29yMQswCQYDVQQGEwJWTjAeFw0xMjAyMDcwOTI3MDBaFw0xNDExMDMwOTEyMjhaMFoxLDAqBgNVBAMMI1ZOUFQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgU3ViIENBMR0wGwYDVQQLDBRWTlBULUNBIFRydXN0IE5ldHdvcjELMAkGA1UEBhMCVk4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKHtabjscY4nLucyIG1yomW32qPFWcPtWt9dhsLW+l8xfVPB5hKed5PY+twCb5pSZAELB+2/AEVnZsjWkHuGmKEcnUZJMGYkYGBGxSR+lQj50QqBzBRN8k7SLRd6hoNLiYRqCMSWKsETg0DwGzYKM+oazbmTpBUra7ZVlSMPBjF1AgMBAAGjggEtMIIBKTCBiQYIKwYBBQUHAQEEfTB7MDYGCCsGAQUFBzAChipodHRwOi8vMjAzLjE2Mi4wLjE2ODo4MDgwL3Jvb3RjYTcyMjAxMi5jZXIwQQYIKwYBBQUHMAGGNWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMB0GA1UdDgQWBBT4xZ6quo5YiN1KRYha/GqNT6Iv/jAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFDffd+YJ9/g/th4oCaOfi9rB0MAgMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvc3ViY2E3MjIwMTIuY3JsMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQA7Hc6Uht22bzV6gJQu9HQyBOe2dCirLDAO6+ilstZBJG1f76enE3Byfxq+n767BTQXfZjAkiUgp5THWe/VsUQ3lwxLo+S8W+dVLqDlXyMvdKwj52PvAV2I1FdSTZOkdwIy1TWFB9ocULwBHlrGtiL+ptMjEziWe/jHSqy0X2EcXw==";

    public boolean verifyCert(String cer) {
        if (cer.equals("MIIDbDCCAtWgAwIBAgIIBVFAeZ5Ph/kwDQYJKoZIhvcNAQEFBQAwZjE4MDYGA1UEAwwvVk5QVCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBUZWNobm9sb2d5IERlbW8gQ0ExHTAbBgNVBAsMFFZOUFQtQ0EgVHJ1c3QgTmV0d29yMQswCQYDVQQGEwJWTjAeFw0xMjAyMDcwOTI3MDBaFw0xNDExMDMwOTEyMjhaMFoxLDAqBgNVBAMMI1ZOUFQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgU3ViIENBMR0wGwYDVQQLDBRWTlBULUNBIFRydXN0IE5ldHdvcjELMAkGA1UEBhMCVk4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKHtabjscY4nLucyIG1yomW32qPFWcPtWt9dhsLW+l8xfVPB5hKed5PY+twCb5pSZAELB+2/AEVnZsjWkHuGmKEcnUZJMGYkYGBGxSR+lQj50QqBzBRN8k7SLRd6hoNLiYRqCMSWKsETg0DwGzYKM+oazbmTpBUra7ZVlSMPBjF1AgMBAAGjggEtMIIBKTCBiQYIKwYBBQUHAQEEfTB7MDYGCCsGAQUFBzAChipodHRwOi8vMjAzLjE2Mi4wLjE2ODo4MDgwL3Jvb3RjYTcyMjAxMi5jZXIwQQYIKwYBBQUHMAGGNWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMB0GA1UdDgQWBBT4xZ6quo5YiN1KRYha/GqNT6Iv/jAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFDffd+YJ9/g/th4oCaOfi9rB0MAgMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvc3ViY2E3MjIwMTIuY3JsMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQA7Hc6Uht22bzV6gJQu9HQyBOe2dCirLDAO6+ilstZBJG1f76enE3Byfxq+n767BTQXfZjAkiUgp5THWe/VsUQ3lwxLo+S8W+dVLqDlXyMvdKwj52PvAV2I1FdSTZOkdwIy1TWFB9ocULwBHlrGtiL+ptMjEziWe/jHSqy0X2EcXw==")) {
            return true;
        } else {
            X509Certificate cert = Utils.StringToX509Certificate(cer);
            X509Certificate root = Utils.StringToX509Certificate("MIIDbDCCAtWgAwIBAgIIBVFAeZ5Ph/kwDQYJKoZIhvcNAQEFBQAwZjE4MDYGA1UEAwwvVk5QVCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBUZWNobm9sb2d5IERlbW8gQ0ExHTAbBgNVBAsMFFZOUFQtQ0EgVHJ1c3QgTmV0d29yMQswCQYDVQQGEwJWTjAeFw0xMjAyMDcwOTI3MDBaFw0xNDExMDMwOTEyMjhaMFoxLDAqBgNVBAMMI1ZOUFQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgU3ViIENBMR0wGwYDVQQLDBRWTlBULUNBIFRydXN0IE5ldHdvcjELMAkGA1UEBhMCVk4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKHtabjscY4nLucyIG1yomW32qPFWcPtWt9dhsLW+l8xfVPB5hKed5PY+twCb5pSZAELB+2/AEVnZsjWkHuGmKEcnUZJMGYkYGBGxSR+lQj50QqBzBRN8k7SLRd6hoNLiYRqCMSWKsETg0DwGzYKM+oazbmTpBUra7ZVlSMPBjF1AgMBAAGjggEtMIIBKTCBiQYIKwYBBQUHAQEEfTB7MDYGCCsGAQUFBzAChipodHRwOi8vMjAzLjE2Mi4wLjE2ODo4MDgwL3Jvb3RjYTcyMjAxMi5jZXIwQQYIKwYBBQUHMAGGNWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMB0GA1UdDgQWBBT4xZ6quo5YiN1KRYha/GqNT6Iv/jAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFDffd+YJ9/g/th4oCaOfi9rB0MAgMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly8yMDMuMTYyLjAuMTY4OjgwODAvc3ViY2E3MjIwMTIuY3JsMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQA7Hc6Uht22bzV6gJQu9HQyBOe2dCirLDAO6+ilstZBJG1f76enE3Byfxq+n767BTQXfZjAkiUgp5THWe/VsUQ3lwxLo+S8W+dVLqDlXyMvdKwj52PvAV2I1FdSTZOkdwIy1TWFB9ocULwBHlrGtiL+ptMjEziWe/jHSqy0X2EcXw==");
            X509CertificateInfo certInfo = null;
            X509Certificate certCA = null;

            try {
                do {
                    certInfo = new X509CertificateInfo(cert);
                    certCA = certInfo.getIssuer();

                    try {
                        cert.verify(certCA.getPublicKey());
                        if (certCA.equals(root)) {
                            return true;
                        }
                    } catch (Exception var7) {
                        System.out.println(var7.getMessage());
                        return false;
                    }

                    cert = certCA;
                } while(!certCA.equals(root));
            } catch (NotFoundURL var8) {
                //Logger.getLogger(Verify.class.getName()).log(Level.SEVERE, (String)null, var8);
            } catch (ConnectErrorException var9) {
                //Logger.getLogger(Verify.class.getName()).log(Level.SEVERE, (String)null, var9);
            }

            return false;
        }
    }

    public List<EnhancedKeyUsage> getKeyUsage(String cer) throws NotFoundAnyKeyUsage, InvalidCerException {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        if (cert == null) {
            throw new InvalidCerException("Chung thu ko dung dinh dang");
        } else {
            List extKeyUsage = null;

            try {
                extKeyUsage = cert.getExtendedKeyUsage();
                if (extKeyUsage == null || extKeyUsage.isEmpty()) {
                    throw new NotFoundAnyKeyUsage();
                }
            } catch (Exception var7) {
                throw new NotFoundAnyKeyUsage();
            }

            List<EnhancedKeyUsage> ret = new ArrayList();
            Iterator var5 = extKeyUsage.iterator();

            while(var5.hasNext()) {
                String ku = (String)var5.next();
                if (ku.equals(EnKeyUsage.ANY_PURPOSE)) {
                    ret.add(EnhancedKeyUsage.ANY_PURPOSE);
                } else if (ku.equals(EnKeyUsage.CLIENT_AUTHENTICATION)) {
                    ret.add(EnhancedKeyUsage.CLIENT_AUTHENTICATION);
                } else if (ku.equals(EnKeyUsage.CODE_SIGNING)) {
                    ret.add(EnhancedKeyUsage.CODE_SIGNING);
                } else if (ku.equals(EnKeyUsage.DOCUMENT_SIGNING)) {
                    ret.add(EnhancedKeyUsage.DOCUMENT_SIGNING);
                } else if (ku.equals(EnKeyUsage.ENCRYPTING_FILE_SYSTEM)) {
                    ret.add(EnhancedKeyUsage.ENCRYPTING_FILE_SYSTEM);
                } else if (ku.equals(EnKeyUsage.FILE_RECOVERY)) {
                    ret.add(EnhancedKeyUsage.FILE_RECOVERY);
                } else if (ku.equals(EnKeyUsage.OCSP_SIGNING)) {
                    ret.add(EnhancedKeyUsage.OCSP_SIGNING);
                } else if (ku.equals(EnKeyUsage.SECURE_EMAIL)) {
                    ret.add(EnhancedKeyUsage.SECURE_EMAIL);
                } else if (ku.equals(EnKeyUsage.SERVER_AUTHENTICATION)) {
                    ret.add(EnhancedKeyUsage.SERVER_AUTHENTICATION);
                } else if (ku.equals(EnKeyUsage.SMART_CARD_LOGON)) {
                    ret.add(EnhancedKeyUsage.SMART_CARD_LOGON);
                } else if (ku.equals(EnKeyUsage.TIME_STAMPING)) {
                    ret.add(EnhancedKeyUsage.TIME_STAMPING);
                } else {
                    ret.add(EnhancedKeyUsage.UNKNOW_KEY_USAGE);
                }
            }

            return ret;
        }
    }

    public OCSPCertStatus verifyCerOCSP(String cer) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP(cer);
    }

    public OCSPCertStatus verifyCerOCSP(String cer, String ocspUrl) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP((String)cer, ocspUrl, (Date)null);
    }

    public OCSPCertStatus verifyCerOCSP(String cer, String ocspUrl, Date dateTime) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP(cer, ocspUrl, dateTime);
    }

    public OCSPCertStatus verifyCerOCSP(ArrayList<X509Certificate> certList, String ocspUrl) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP((ArrayList)certList, ocspUrl, (Date)null);
    }

    public OCSPCertStatus verifyCerOCSP(ArrayList<X509Certificate> certList, String ocspUrl, Date dateTime) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP(certList, ocspUrl, dateTime);
    }

    public CRLCertStatus verifyCerCRL(String cer) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        return this.crlConnection.checkCerCRL(cer);
    }

    public CRLCertStatus verifyCerCRL(String cer, String urlCrl, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        return this.crlConnection.checkCerCRL(cer, urlCrl, dateTime);
    }

    public CRLCertStatus verifyCerCRLFromFile(String cer, String crlFile, Date dateTime) throws InvalidCerException, ConnectErrorException, NotFoundURL {
        return this.crlConnection.checkCerCRLFromFile(cer, crlFile, dateTime);
    }


    private ICRLConnection getCrlConnection() {
        return this.crlConnection;
    }

    private void setCrlConnection(ICRLConnection crlConnection) {
        this.crlConnection = crlConnection;
    }

    private IOCSPConnection getOcspConnection() {
        return this.ocspConnection;
    }

    private void setOcspConnection(IOCSPConnection ocspConnection) {
        this.ocspConnection = ocspConnection;
    }


    public boolean isExpiredCer(String cer) throws InvalidCerException {
        X509Certificate cert = Utils.StringToX509Certificate(cer);
        if (cert == null) {
            throw new InvalidCerException();
        } else {
            try {
                cert.checkValidity(new Date());
                return false;
            } catch (CertificateExpiredException var4) {
                throw new InvalidCerException(var4.getMessage());
            } catch (CertificateNotYetValidException var5) {
                throw new InvalidCerException(var5.getMessage());
            }
        }
    }



    public void loadCRLFileFromURL(String url, String pathSaveFile) throws ConnectErrorException {
        int size = 1024;
        OutputStream outStream = null;
        URLConnection uCon = null;
        InputStream is = null;

        try {
            int ByteWritten = 0;
            URL Url = new URL(url);
            outStream = new BufferedOutputStream(new FileOutputStream(pathSaveFile));
            uCon = Url.openConnection();

            try {
                is = uCon.getInputStream();
            } catch (IOException var21) {
                throw new ConnectErrorException("Can't connect to CRL Store throught URL");
            }

            int ByteRead;
            for(byte[] buf = new byte[size]; (ByteRead = is.read(buf)) != -1; ByteWritten += ByteRead) {
                outStream.write(buf, 0, ByteRead);
            }

            System.out.println("Downloaded Successfully.");
            System.out.println("File name:\"" + pathSaveFile + "\"\nNo ofbytes :" + ByteWritten);
        } catch (Exception var22) {
            System.out.println(var22);
        } finally {
            try {
                is.close();
                outStream.close();
            } catch (Exception var20) {
                throw new ConnectErrorException("Can't connect to CRL Store throught URL");
            }
        }

    }

    public boolean isHasAnyPurpose(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.ANY_PURPOSE, cer);
    }

    public boolean isHasServerAuthentication(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.SERVER_AUTHENTICATION, cer);
    }

    public boolean isHasClientAuthentication(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.CLIENT_AUTHENTICATION, cer);
    }

    public boolean isHasCodeSigning(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.CODE_SIGNING, cer);
    }

    public boolean isHasSecureEmail(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.SECURE_EMAIL, cer);
    }

    public boolean isHasTimeStamping(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.TIME_STAMPING, cer);
    }

    public boolean isHasOcspSigning(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.OCSP_SIGNING, cer);
    }

    public boolean isHasSmartCardLogon(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.SMART_CARD_LOGON, cer);
    }

    public boolean isHasEncryptingFileSystem(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.ENCRYPTING_FILE_SYSTEM, cer);
    }

    public boolean isHasDocumentSigning(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.DOCUMENT_SIGNING, cer);
    }

    public boolean isHasFileRecovery(String cer) throws InvalidCerException, NotFoundAnyKeyUsage {
        return this.isHasEnKeyUsage(EnhancedKeyUsage.FILE_RECOVERY, cer);
    }

    private boolean isHasEnKeyUsage(EnhancedKeyUsage keyUsage, String cer) throws NotFoundAnyKeyUsage, InvalidCerException {
        List<EnhancedKeyUsage> keyUsages = this.getKeyUsage(cer);
        return keyUsages.contains(keyUsage);
    }

    public OCSPCertStatus verifyCerOCSP(X509Certificate cert, String ocspUrl, Date dateTime) throws NotFoundURL, InvalidCerException, ConnectErrorException {
        return this.ocspConnection.checkCerOCSP(cert, ocspUrl, dateTime);
    }
}
