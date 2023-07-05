package fpt.signature.sign.license;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import com.google.gson.Gson;
import fpt.signature.sign.core.CertTools;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class LicenseManager {
    private static final Logger log = Logger.getLogger(LicenseManager.class);
    public static final String TIME_FOMART = "MM/dd/yyyy HH:mm:ss";
    public static final String LICENSE_REQUEST = "LICENSE_REQUEST";
    public static final String LICENSE_VALUE = "LICENSE_VALUE";
    private static final String VALID_FROM = "ValidFrom";
    private static final String VALID_TO = "ValidTo";
    private static final String OFFICIAL = "Official";
    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuuuTgMFnxwncIaC+rV4hSQaJvdzbp77PYV3OEKjDBf/mCYGo5X9zu2EPQsI1uza09kD5Ud7oZ4InEKbnPI3ZiSgH+6yJbT2Lq7EbCgjLcpx4MABlnigB1OC7VKJKtvfAtZiBdEJyO/DrH86Ze/aoKUQ1Okb/9EOP+JMDEgKVpOAeQNKKE07M+qAisSVAcvFrugY8kXrzJej7QJE1WPtejlxJvtklGechvWjcg7IUCWxRXkDJM1a4a0dE9LCd/j0OQivD7Xkfk3EKUqXSuDvKWG5fq+tnrECWULV5DM+IlHFCaYVkj81WGzOTXhFbOTSbrBNK6lHV5/plltdBrWf4kQIDAQAB";
    public static final String SIGNER = "MIIFCzCCA/OgAwIBAgIQVAEBBCUx9I+14SUdGmYwkjANBgkqhkiG9w0BAQUFADBuMQswCQYDVQQGEwJWTjEYMBYGA1UEChMPRlBUIENvcnBvcmF0aW9uMR8wHQYDVQQLExZGUFQgSW5mb3JtYXRpb24gU3lzdGVtMSQwIgYDVQQDExtGUFQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwNzAxMDgyNjI3WhcNMjQwNjAxMTEyNjE1WjBUMQswCQYDVQQGEwJWTjEkMCIGA1UEAwwbRlBUIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MR8wHQYKCZImiZPyLGQBAQwPTVNUOjA5MzMxMjMxMjM3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxOzVG+x0q/4chL5UuqpF9PPjA35kC2cLhPfE2a9mI9ej8dzFS5ykuG3vEuMaTVWgWH1vMp/SRbUAM6WXYeDaGRdo6gfnXjmqUHQaSJcJX97UvNnYS2k+K2aUCGG7xcqNud2qfuecOp+iztJ+baJWkDTm2D+OywjA9tIDteNpu94LCNA9evGTmSEMQE8+n1D2xA1leBYZr95clYdZ+Rfhaj84Nnn1ZJpiuT9jh4hSN0Dvpj9fajNA8gVobqsC4zb0cgsOl0imXtXUuCaPqbrfIK6BAXPJy5Cc52WvMnyfy+vmgTQIy1kzG5RUOVIouNy2uv3yj3dVEajqtqNKON1FfQIDAQABo4IBvTCCAbkwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSaphGlCw6MEi0SLfWW1uUXayA8LzCBqAYIKwYBBQUHAQEEgZswgZgwNwYIKwYBBQUHMAKGK2h0dHA6Ly9wdWJsaWMucm9vdGNhLmdvdi52bi9jcnQvbWljbnJjYS5jcnQwOAYIKwYBBQUHMAKGLGh0dHA6Ly9kaWNodnVkaWVudHUuZnB0LmNvbS52bi9jcnQvZnB0Y2EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcDIuZmlzLmNvbS52bjBPBgNVHSAESDBGMEQGCysGAQQBge0DAQQBMDUwMwYIKwYBBQUHAgEWJ2h0dHA6Ly9kaWNodnVkaWVudHUuZnB0LmNvbS52bi9jcHMuaHRtbDA0BgNVHSUELTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCSqGSIb3LwEBBTAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8vY3JsMi5maXMuY29tLnZuMB0GA1UdDgQWBBSnXIw64TW/bU3kMfjjvvIR24mtizAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBABldamnk41jMYoJ7Ts9GBp9bK7zf0c5vnUsklX0vgEUeV0nAYptBxUToY3cc2ndoCQUK3V7XkKK0vK8kmdiXAVRVSzqngQtb4T0DsnHgr+MYCgyJqBJkBL3Wwas/BUH4QA/HCFlhm4i9rzug0SUdGgG80oi6/AGRjAsQenlOZc4rLUTuxsFDEFS4sf0zk2Rq5Y7mQs3WFP0iVp7fg8UlkiV+0FDuN+eTLGoAuen5iKEYo+OfdprwoW3elg6rvlytMnryzimBvgKLQONroDVsUSHtfJz5mkjuMU+at9xgOf+ao89gLA8TmjqUtWxGr9/75oZdZHaYVYv0xuArvCUtppI=";
    private static String _lastError = "";
    private static final char[] HEX_CHARS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String generateRequest(String appVersion, String moduleValues) throws Exception {
        String request = createRequest(appVersion, moduleValues);


        PublicKey pubKey = CertTools.StringToX509Certificate(SIGNER).getPublicKey();
        byte[] encrypt = RSAProvider.encrypt(request.getBytes(), pubKey);
        String requestEncoded = Base64.toBase64String(encrypt);
        String requestpath = getPath("REQUEST.lis");

        try {
            FileUtils.writeStringToFile(new File(requestpath), requestEncoded);
        } catch (IOException var11) {
            _lastError = var11.getMessage();
            log.error("License exception '" + var11.getMessage() + "'");
            return "";
        }

        return requestEncoded;

    }

    public static String getLastError() {
        return _lastError;
    }

    public static boolean changeLicense(String license) {
        boolean check = false;

        try {
            check = checkLicense(license);
        } catch (CryptoException var5) {
            _lastError = var5.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var5);
        }

        if (!check) {
            return false;
        } else {
            String licensePath = getPath("LICENSE.lis");

            try {
                FileUtils.writeStringToFile(new File(licensePath), license);
                return true;
            } catch (IOException var4) {
                _lastError = var4.getMessage();
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var4);
                return false;
            }
        }
    }

    private static boolean checkMachine(byte[] license) {
        String os = System.getProperty("os.name").toLowerCase();
        IBiosManager checker = null;
        if (os.contains("win")) {
            os = "windows";
        } else if (os.contains("linux")) {
            os = "linux";
        }

        try {
            checker = BiosManagerFactory.getInstance(os);
        } catch (Exception var14) {
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var14);
            return false;
        }

        String serial = null;

        try {
            serial = checker.getSerialNumber();
        } catch (Exception var13) {
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, "Cannot get service serial number", var13);
            return false;
        }

        if (serial == null || "".equals(serial)) {
            log.warn("Machine serialnumber get failed. Try get Bios charactis");
            serial = checker.getBiosCharactis();
        }

        if (serial != null && !"".equals(serial)) {
            log.info("Machine serial number: " + serial);

            try {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] hashValue = sha256.digest(serial.getBytes());
                serial = toHexString(hashValue);
            } catch (NoSuchAlgorithmException var12) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var12);
                return false;
            }

            log.info("Machine serial number hex: " + serial);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Document signedLicense = null;

            try {
                DocumentBuilder builder = factory.newDocumentBuilder();
                signedLicense = builder.parse(new ByteArrayInputStream(license));
                Node machineId = signedLicense.getElementsByTagName("LicenseID").item(0);
                String machine = machineId.getFirstChild().getNodeValue();
                log.info("License machine ID: " + serial);
                return machine.equals(serial);
            } catch (SAXException var9) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var9);
                return false;
            } catch (IOException var10) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var10);
                return false;
            } catch (ParserConfigurationException var11) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var11);
                return false;
            }
        } else {
            log.warn("Bios charactis get failed");
            return false;
        }
    }

    private static String toHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];

        for(int j = 0; j < bytes.length; ++j) {
            int v = bytes[j] & 255;
            hexChars[j * 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHARS[v & 15];
        }

        return new String(hexChars);
    }

    public static boolean checkLicense() throws CryptoException {
        String licensePath = getPath("LICENSE.lis");

        String license;
        try {
            license = FileUtils.readFileToString(new File(licensePath));
        } catch (IOException var3) {
            _lastError = var3.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var3);
            throw new CryptoException("Check license failed");
        }

        return checkLicense(license);
    }

    public static String getLicenseValue() {
        String licensePath = getPath("LICENSE.lis");
        Gson gson = new Gson();
        HashMap map = new HashMap();

        try {
            String license = FileUtils.readFileToString(new File(licensePath));
            if (!checkLicense(license)) {
                map.put("LICENSEBASE", getLastError());
                return gson.toJson(map);
            } else {
                byte[] licenseBytes = Base64.decode(license);
                List<Certificate> trustAnchors = new ArrayList();
                ValidationData signedData = new ValidationData(licenseBytes, trustAnchors, 0);
                String validFrom = getLicenseTime(signedData, "ValidFrom");
                String validTo = getLicenseTime(signedData, "ValidTo");
                if ("00/00/0000 00:00:00".equals(validTo)) {
                    validTo = "NOT EXPIRED";
                }

                map.put("SIGNER", getLicenseSigner(license));
                String licenseOfficial = getLicenseTime(signedData, "Official");
                log.info("licenseOfficial: " + licenseOfficial);
                map.put("ValidFrom", validFrom);
                if (licenseOfficial == null || !licenseOfficial.equals("1")) {
                    map.put("ValidTo", validTo);
                }

                map.put("LICENSEBASE", license);
                return gson.toJson(map);
            }
        } catch (IOException var10) {
            _lastError = var10.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var10);
            map.put("LICENSEBASE", "eSignature Server is not actived.");
            return gson.toJson(map);
        } catch (CryptoException var11) {
            _lastError = var11.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var11);
            map.put("LICENSEBASE", _lastError);
            return gson.toJson(map);
        }
    }

    public static String getRequestValue() {
        String licensePath = getPath("REQUEST.lis");

        try {
            return FileUtils.readFileToString(new File(licensePath));
        } catch (IOException var2) {
            _lastError = var2.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var2);
            return "";
        }
    }

    public static boolean checkLicense(String licenseBase64) throws CryptoException {
        Object var1 = null;

        byte[] licenseBytes;
        try {
            licenseBytes = Base64.decode(licenseBase64);
        } catch (Exception var7) {
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var7);
            throw new CryptoException("License invalid format");
        }

        if (!checkMachine(licenseBytes)) {
            throw new CryptoException("License not match this machine.");
        } else {
            List<Certificate> trustAnchors = new ArrayList();
            ValidationData signedData = new ValidationData(licenseBytes, trustAnchors, 0);
            XmlValidator validator = new XmlValidator();

            try {
                ValidationResponseData response = validator.verify(signedData);
                if (response.getResutCode() != 0) {
                    throw new CryptoException("License invalid: " + response.getMessage());
                } else if (!CheckValidTime(signedData)) {
                    throw new CryptoException("The license has expired or is not yet valid");
                } else {
                    return true;
                }
            } catch (SignServerSignaturesException var6) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var6);
                throw new CryptoException("License invalid. " + var6.getMessage());
            }
        }
    }

    private static String createRequest(String appVersion, String moduleValues) throws Exception {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            os = "windows";
        } else if (os.contains("linux")) {
            os = "linux";
        }

        IBiosManager checker;
        try {
            checker = BiosManagerFactory.getInstance(os);
        } catch (Exception var19) {
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var19);
            return null;
        }

        String serial = checker.getSerialNumber();
        if (serial == null || "".equals(serial)) {
            serial = checker.getBiosCharactis();
        }

        if (serial != null && !"".equals(serial)) {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();

            try {
                DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                Document doc = docBuilder.newDocument();
                Element rootElement = doc.createElement("LicenseRequest");
                doc.appendChild(rootElement);
                Element id = doc.createElement("RequestID");
                id.appendChild(doc.createTextNode(serial));
                rootElement.appendChild(id);
                Element app = doc.createElement("AppVersion");
                app.appendChild(doc.createTextNode(appVersion));
                rootElement.appendChild(app);
                Element modules = doc.createElement("Modules");
                modules.appendChild(doc.createTextNode(moduleValues));
                rootElement.appendChild(modules);
                Element time = doc.createElement("CreatedTime");
                time.appendChild(doc.createTextNode((new Date()).toString()));
                rootElement.appendChild(time);
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                DOMSource source = new DOMSource(doc);
                ByteArrayOutputStream outStream = new ByteArrayOutputStream();
                StreamResult result = new StreamResult(outStream);
                transformer.transform(source, result);
                return new String(outStream.toByteArray());
            } catch (ParserConfigurationException var18) {
                java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var18);
                return null;
            }
        } else {
            throw new Exception("Cannot get server serialnumber");
        }
    }

    public static Boolean CheckValidTime(ValidationData signedData) {
        String validFrom = getLicenseTime(signedData, "ValidFrom");
        String validTo = getLicenseTime(signedData, "ValidTo");
        Date dateVaildFrom = ConvertStringToTime(validFrom);
        log.info("Date valid from: " + dateVaildFrom);
        Date dateVaildTo = ConvertStringToTime(validTo);
        log.info("Date valid to: " + dateVaildTo);
        Date dateTimeNow = new Date();
        log.info("Now: " + dateTimeNow);
        if (null != dateVaildFrom && !dateTimeNow.before(dateVaildFrom)) {
            if (validTo != null && validTo.equals("00/00/0000 00:00:00")) {
                return true;
            } else if (null != validTo && !dateTimeNow.after(dateVaildTo)) {
                return true;
            } else {
                log.error("License is expired. Valid to " + validTo);
                return false;
            }
        } else {
            log.error("License not yet valid. Valid from " + validFrom);
            return false;
        }
    }

    private static String getLicenseTime(ValidationData signedData, String tagName) {
        try {
            Document doc = XmlUtil.loadXmlDocument(signedData.getSignedData());
            NodeList timeNode = doc.getElementsByTagName(tagName);
            if (timeNode.getLength() != 0) {
                String time = timeNode.item(0).getTextContent();
                return time;
            } else {
                return null;
            }
        } catch (SignServerSignaturesException var5) {
            return null;
        }
    }

    private static String getLicenseMachineCode(ValidationData signedData) {
        return "";
    }

    private static String getLicenseSigner(String licenseBase64) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            byte[] signerCertBytes = Base64.decode("MIIC9TCCAd2gAwIBAgIEXwwFZDANBgkqhkiG9w0BAQsFADApMQswCQYDVQQGEwJWTjEaMBgGA1UEAwwRRVNJR05BVFVSRSBTRVJWRVIwHhcNMjAwNzEzMDY1NTMyWhcNMzAwNzEzMDY1NTMyWjApMQswCQYDVQQGEwJWTjEaMBgGA1UEAwwRRVNJR05BVFVSRSBTRVJWRVIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC665OAwWfHCdwhoL6tXiFJBom93Nunvs9hXc4QqMMF/+YJgajlf3O7YQ9CwjW7NrT2QPlR3uhngicQpuc8jdmJKAf7rIltPYursRsKCMtynHgwAGWeKAHU4LtUokq298C1mIF0QnI78Osfzpl79qgpRDU6Rv/0Q4/4kwMSApWk4B5A0ooTTsz6oCKxJUBy8Wu6BjyRevMl6PtAkTVY+16OXEm+2SUZ5yG9aNyDshQJbFFeQMkzVrhrR0T0sJ3+PQ5CK8PteR+TcQpSpdK4O8pYbl+r62esQJZQtXkMz4iUcUJphWSPzVYbM5NeEVs5NJusE0rqUdXn+mWW10GtZ/iRAgMBAAGjJTAjMBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdDwQFAwMH0YAwDQYJKoZIhvcNAQELBQADggEBABIGYDeH350SBMDiiPDTKS6P2rK3UndYCtJRnDxvtp1MaAQblYRqxY8V8OIEmLyJEhzCNn0jO3S5esIG1Ql5OepJKuxkrT8sMHy/YuvSk7KjDgVf+GGDt112VmZZKaTBDgKHo4bha5463x5+pqD6/GKNcSMdIMH7sndMYDEKPf9Ueionnud3V7E4Zkilf2HNUkBc+KsI3TrMLUhA91IYgn9C2iE3qn/BEmRydROA71vkKZzARNXQ7yKvFo1pTazEKS9uGKpzUE8fV+58RGXuhXwilyWw//+D/X6f2f1nwc/7pOepsBszeopK5aNZqCCINwGO711lxFVvUdzraY0L+wQ=");
            ByteArrayInputStream certStream = new ByteArrayInputStream(signerCertBytes);
            Certificate signerInner = factory.generateCertificate(certStream);
            X509Certificate inner = (X509Certificate)signerInner;
            String subjectDN = inner.getSubjectDN().getName();
            LdapName name = new LdapName(subjectDN);
            Iterator var8 = name.getRdns().iterator();

            while(var8.hasNext()) {
                Rdn rdn = (Rdn)var8.next();
                if (rdn != null && rdn.getValue() != null && "CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (CertificateException var10) {
            java.util.logging.Logger.getLogger(XmlValidator.class.getName()).log(Level.SEVERE, (String)null, var10);
        } catch (InvalidNameException var11) {
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var11);
        }

        return "";
    }

    public static Date ConvertStringToTime(String s) {
        if (s != null) {
            try {
                SimpleDateFormat sdf1 = new SimpleDateFormat();
                sdf1.applyPattern("MM/dd/yyyy HH:mm:ss");
                Date date = sdf1.parse(s);
                return date;
            } catch (ParseException var3) {
                System.out.println("Exception " + var3);
            }
        }

        return null;
    }

    private static String getPath(String fileName) {

        String folderRuntime = System.getProperty("user.dir");
        System.out.println("folderRuntime: " + folderRuntime);
        Path path = Paths.get(folderRuntime, fileName);

        try {
            String licensePath = path.toString();
            return licensePath;
        } catch (Exception var4) {
            _lastError = var4.getMessage();
            java.util.logging.Logger.getLogger(LicenseManager.class.getName()).log(Level.SEVERE, (String)null, var4);
            return "";
        }
    }
}
