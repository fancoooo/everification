package fpt.signature.sign.utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import fpt.signature.sign.core.X509CertificateInfo;
import fpt.signature.sign.ex.ConnectErrorException;
import fpt.signature.sign.ex.InvalidCerException;
import fpt.signature.sign.ex.NotFoundURL;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class Utils {
    private static final String MIC_National_Root_CA = "MIC National Root CA";
    private static final String MIC_National_Root_CA_Thumprint = "MIC_National_Root_CA_Thumprint";

    public X509Certificate readCert(String path) throws CertificateException, FileNotFoundException {
        X509Certificate rootCert = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream isCertCA = this.getClass().getResourceAsStream(path);
        if (isCertCA == null) {
            throw new FileNotFoundException();
        } else {
            rootCert = (X509Certificate)cf.generateCertificate(isCertCA);
            return rootCert;
        }
    }

    public String readBase64CertFromFile(String path) throws CertificateException, FileNotFoundException {
        X509Certificate cert = this.readCert(path);
        return X509CertificateToString(cert);
    }

    public static X509Certificate StringToX509Certificate(String cer) {
        X509Certificate certificate = null;

        try {
            byte[] cerbytes = Base64.decode(cer);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cerbytes));
            return certificate;
        } catch (CertificateException var4) {
            return null;
        }
    }

    public static String X509CertificateToString(X509Certificate cer) {
        String ret = "";

        try {
            byte[] cerByte = cer.getEncoded();
            ret = ret + Base64Utils.base64Decode(cerByte);
        } catch (CertificateEncodingException var3) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var3);
        }

        return ret;
    }

    public static X509Certificate getCerFromCerFile(String filename) {
        FileInputStream is = null;

        try {
            is = new FileInputStream(filename);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(is);
            X509Certificate var4 = cert;
            return var4;
        } catch (CertificateException var16) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var16);
        } catch (FileNotFoundException var17) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var17);
        } finally {
            try {
                is.close();
            } catch (IOException var15) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var15);
            }

        }

        return null;
    }

    public void loadCRL(URL url) {
        try {
            InputStream in = url.openStream();
            BufferedReader dis = new BufferedReader(new InputStreamReader(in));
            StringBuilder fBuf = new StringBuilder();
            BufferedWriter out = new BufferedWriter(new FileWriter("vn.crl"));

            String line;
            while((line = dis.readLine()) != null) {
                fBuf.append(line).append("\n");
                out.write(processString(line));
            }

            in.close();
            System.out.print(fBuf);
            out.close();
        } catch (IOException var7) {
            System.out.println("IO Exception = " + var7);
        }
    }

    public static Document StringToDocument(String xmlString) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new FileInputStream(xmlString));
    }

    public static Document convertStringToXMLDocument(String xmlString) throws ParserConfigurationException, SAXException, IOException
    {
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        //API to obtain DOM Document instance
        DocumentBuilder builder = null;
        //Create DocumentBuilder with default configuration
        builder = factory.newDocumentBuilder();

        //Parse the content to Document object
        Document doc = builder.parse(new InputSource(new StringReader(xmlString)));
        return doc;
    }

    public static String DocumentToString(Document doc, Transformer trans) throws TransformerException {
        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(doc);
        trans.transform(source, result);
        String xmlString = result.getWriter().toString();
        return xmlString;
    }

    public static String processString(String line) {
        return (new StringBuilder(line)).reverse().toString();
    }

    public static String readFile(String filename) {
        String content = null;
        File file = new File(filename);

        try {
            FileReader reader = new FileReader(file);
            char[] chars = new char[(int)file.length()];
            reader.read(chars);
            content = new String(chars);
            reader.close();
        } catch (IOException var5) {
            var5.printStackTrace();
        }

        return content;
    }

    public static byte[] loadFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
        long length = file.length();
        if (length > 2147483647L) {
        }

        byte[] bytes = new byte[(int)length];
        int offset = 0;

        int numRead;
        for(boolean var6 = false; offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0; offset += numRead) {
        }

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        } else {
            is.close();
            return bytes;
        }
    }

    public static byte[] readBytesFromFile(String inputPath) throws IOException {
        ByteArrayOutputStream ous = null;
        FileInputStream ios = null;

        try {
            byte[] buffer = new byte[4096];
            ous = new ByteArrayOutputStream();
            ios = new FileInputStream(new File(inputPath));
            boolean var4 = false;

            int read;
            while((read = ios.read(buffer)) != -1) {
                ous.write(buffer, 0, read);
            }
        } finally {
            try {
                if (ous != null) {
                    ous.close();
                }
            } catch (IOException var13) {
            }

            try {
                if (ios != null) {
                    ios.close();
                }
            } catch (IOException var12) {
            }

        }

        return ous.toByteArray();
    }

    public static String getAuthorityKeyIdentifier(X509Certificate certificate) throws CertificateException {
        byte[] result = null;
        String keyIdentifierHex = null;

        try {
            byte[] extvalue = certificate.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
            if (extvalue != null) {
                AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
                result = keyId.getKeyIdentifier();
            }

            if (result != null) {
                keyIdentifierHex = new String(Hex.encode(result));
            }

            return keyIdentifierHex;
        } catch (IOException var5) {
            throw new CertificateException("Error retrieving certificate authority key identifier for subject " + certificate.getSubjectX500Principal().getName(), var5);
        }
    }

    private static String getAuthorityKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
        if (extvalue == null) {
            return null;
        } else {
            DEROctetString oct = (DEROctetString)((DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(extvalue))).readObject());
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()))).readObject());
            AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier(apki);
            return new String(keyId.getKeyIdentifier());
        }
    }

    public static String getSubjectKeyIdentifier(X509Certificate certificate) throws CertificateException {
        byte[] result = null;
        String keyIdentifierHex = null;

        try {
            byte[] extvalue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
            if (extvalue != null) {
                SubjectKeyIdentifier keyId = new SubjectKeyIdentifierStructure(extvalue);
                result = keyId.getKeyIdentifier();
            }

            if (result != null) {
                keyIdentifierHex = new String(Hex.encode(result));
            }

            return keyIdentifierHex;
        } catch (IOException var5) {
            throw new CertificateException("Error retrieving certificate subject key identifier for subject " + certificate.getSubjectX500Principal().getName(), var5);
        }
    }

    private static String getSubjectKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
        if (extvalue == null) {
            return null;
        } else {
            ASN1OctetString str = ASN1OctetString.getInstance((new ASN1InputStream(new ByteArrayInputStream(extvalue))).readObject());
            SubjectKeyIdentifier keyId = SubjectKeyIdentifier.getInstance((new ASN1InputStream(new ByteArrayInputStream(str.getOctets()))).readObject());
            return new String(keyId.getKeyIdentifier());
        }
    }

    public static ArrayList<X509Certificate> getTrustPathArranged(ArrayList<String> certs) {
        if (certs == null) {
            return null;
        } else {
            try {
                ArrayList<X509Certificate> certsList = new ArrayList();
                X509Certificate certTpm = null;
                int i = 0;

                do {
                    String cert = (String)certs.get(i);
                    ++i;
                    X509Certificate certX509 = StringToX509Certificate(cert);
                    if (certX509.getBasicConstraints() == -1) {
                        certsList.add(certX509);
                        certTpm = certX509;
                        certs.remove(cert);
                        i = 0;
                    } else if (certTpm != null) {
                        String subjectKeyId = getSubjectKeyIdentifier(certX509);
                        String authorityKeyId = getAuthorityKeyIdentifier(certTpm);
                        if (subjectKeyId.equals(authorityKeyId)) {
                            certsList.add(certX509);
                            certTpm = certX509;
                            certs.remove(cert);
                            i = 0;
                        }
                    }
                } while(!certs.isEmpty() && i < certs.size());

                return certsList;
            } catch (CertificateException var8) {
                return null;
            }
        }
    }

    public static X509Certificate getIssuerCert(X509Certificate cert) throws NotFoundURL, ConnectErrorException {
        if (IsSelfCert(cert)) {
            return null;
        } else {
            X509CertificateInfo cerInfo = new X509CertificateInfo(cert);
            X509Certificate issuer = cerInfo.getIssuer();
            String jboss_home = null;
            if (issuer == null) {
                System.out.println("get issuer cert from config file");
                String[] issuerName = cert.getIssuerDN().getName().split(",");
                String name = null;
                String[] var6 = issuerName;
                int var7 = issuerName.length;

                for(int var8 = 0; var8 < var7; ++var8) {
                    String ob = var6[var8];
                    if (ob.contains("CN=")) {
                        name = ob.trim().substring(ob.trim().lastIndexOf("CN=") + 3);
                        break;
                    }
                }

                if (name == null) {
                    return issuer;
                }

                PropertiesConfiguration cerConfig = null;

                String certIsser;
                File fCertIssuer;
                try {
                    jboss_home = System.getenv("JBOSS_HOME");
                    if (jboss_home == null) {
                        certIsser = System.getProperty("user.dir");
                        jboss_home = certIsser.substring(0, certIsser.length() - "bin".length());
                    }

                    Path path = Paths.get(jboss_home, "standalone", "configuration", "issuer-config", "config.properties");
                    fCertIssuer = new File(path.toString());
                    if (fCertIssuer.exists() && !fCertIssuer.isDirectory()) {
                        cerConfig = new PropertiesConfiguration(path.toString());
                    }
                } catch (ConfigurationException var10) {
                    //Logger.getLogger(CRLConnection.class.getName()).log(Level.SEVERE, (String)null, var10);
                }

                if (cerConfig != null) {
                    certIsser = cerConfig.getString(name.replace(" ", "_"));
                    if (certIsser != null) {
                        fCertIssuer = new File(certIsser);
                        if (fCertIssuer.exists() && !fCertIssuer.isDirectory()) {
                            issuer = getCerFromCerFile(certIsser);
                        } else {
                            Path pathFileIssuer = Paths.get(jboss_home, "standalone", "configuration", "issuer-config", certIsser);
                            issuer = getCerFromCerFile(pathFileIssuer.toString());
                        }
                    }
                }
            }

            return issuer;
        }
    }

    public static Boolean IsMICCertificate(X509Certificate cert) throws NotFoundURL, ConnectErrorException {
        X509CertificateInfo cerInfo = new X509CertificateInfo(cert);
        X509Certificate issuer = cerInfo.getIssuer();
        if (issuer == null) {
            String[] issuerName = cert.getIssuerDN().getName().split(",");
            String name = null;
            String[] var5 = issuerName;
            int var6 = issuerName.length;

            for(int var7 = 0; var7 < var6; ++var7) {
                String ob = var5[var7];
                if (ob.contains("CN=")) {
                    name = ob.trim().substring(ob.trim().lastIndexOf("CN=") + 3);
                    break;
                }
            }

            if (name == null) {
                return false;
            }

            if (name.equals("MIC National Root CA")) {
                PropertiesConfiguration cerConfig = null;

                String MICThumprint;
                String thumprintCert;
                try {
                    MICThumprint = System.getenv("JBOSS_HOME");
                    if (MICThumprint == null) {
                        thumprintCert = System.getProperty("user.dir");
                        MICThumprint = thumprintCert.substring(0, thumprintCert.length() - "bin".length());
                    }

                    Path path = Paths.get(MICThumprint, "standalone", "configuration", "issuer-config", "config.properties");
                    File f = new File(path.toString());
                    if (f.exists() && !f.isDirectory()) {
                        cerConfig = new PropertiesConfiguration(path.toString());
                    }
                } catch (ConfigurationException var11) {
                    //Logger.getLogger(CRLConnection.class.getName()).log(Level.SEVERE, (String)null, var11);
                }

                if (cerConfig != null) {
                    MICThumprint = cerConfig.getString("MIC_National_Root_CA_Thumprint");
                    if (MICThumprint != null) {
                        try {
                            thumprintCert = getThumbPrint(cert);
                            if (thumprintCert != null && thumprintCert.equals(MICThumprint)) {
                                return true;
                            }
                        } catch (NoSuchAlgorithmException var9) {
                            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var9);
                        } catch (CertificateEncodingException var10) {
                            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var10);
                        }
                    }
                }
            }
        }

        return false;
    }

    public static Boolean IsSelfCert(X509Certificate cert) throws NotFoundURL, ConnectErrorException {
        try {
            String subjectKeyId = getSubjectKeyIdentifier(cert);
            String authKeyId = getAuthorityKeyIdentifier(cert);
            if (authKeyId == null) {
                return true;
            }

            if (subjectKeyId != null && !"".equals(subjectKeyId) && subjectKeyId.equals(authKeyId)) {
                return true;
            }
        } catch (CertificateException var3) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, (String)null, var3);
        }

        return false;
    }

    public static String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return hexify(digest);
    }

    public static String hexify(byte[] bytes) {
        char[] hexDigits = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for(int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 240) >> 4]);
            buf.append(hexDigits[bytes[i] & 15]);
        }

        return buf.toString();
    }

    public static ArrayList<X509Certificate> getCertChain(String cer) throws InvalidCerException {
        ArrayList<X509Certificate> certChain = null;
        X509Certificate cert = StringToX509Certificate(cer);
        if (cert == null) {
            throw new InvalidCerException("Base64 Certificate of user input incorrect");
        } else {
            certChain = new ArrayList();
            certChain.add(cert);
            X509Certificate certTemp = null;
            int i = 0;

            do {
                try {
                    certTemp = getIssuerCert((X509Certificate)certChain.get(i));
                    if (certTemp == null) {
                        break;
                    }

                    certChain.add(certTemp);
                    ++i;
                } catch (ConnectErrorException | NotFoundURL var6) {
                    //Logger.getLogger(ValidateCertificate.class.getName()).log(Level.SEVERE, (String)null, var6);
                }
            } while(i < 20);

            return certChain;
        }
    }

    public static ArrayList<X509Certificate> buildCertChain(String cer, String isserCert) throws InvalidCerException {
        ArrayList<X509Certificate> certChain = null;
        X509Certificate x509UserCert = StringToX509Certificate(cer);
        X509Certificate x509IsserCert = StringToX509Certificate(isserCert);
        if (x509UserCert != null && x509IsserCert != null) {
            certChain = new ArrayList();
            certChain.add(x509UserCert);
            certChain.add(x509IsserCert);
            X509Certificate certTemp = null;
            int i = 1;

            do {
                try {
                    certTemp = getIssuerCert((X509Certificate)certChain.get(i));
                    if (certTemp == null) {
                        break;
                    }

                    certChain.add(certTemp);
                    ++i;
                } catch (ConnectErrorException | NotFoundURL var8) {
                    //Logger.getLogger(ValidateCertificate.class.getName()).log(Level.SEVERE, (String)null, var8);
                }
            } while(i < 20);

            return certChain;
        } else {
            throw new InvalidCerException("Base64 Certificate of user input incorrect");
        }
    }

    public static String ConvertTimeToString(Date t) {
        if (t != null) {
            try {
                SimpleDateFormat sdf1 = new SimpleDateFormat();
                sdf1.applyPattern("dd/MM/yyyy HH:mm:ss");
                String s = sdf1.format(t);
                return s;
            } catch (Exception var3) {
            }
        }

        return null;
    }

    public static Date ConvertStringTZToTime(String iso8601string, String format) {
        if (iso8601string != null) {
            try {
                Calendar calendar = GregorianCalendar.getInstance();
                String s = iso8601string.replace("Z", "+00:00");
                s = s.substring(0, 22) + s.substring(23);
                if (format.contains("T")) {
                    format = "yyyy-MM-dd'T'HH:mm:ssZ";
                }

                Date date = (new SimpleDateFormat(format)).parse(s);
                return date;
            } catch (ParseException var5) {
                System.out.println("Exception " + var5);
            }
        }

        return null;
    }

    public static String ConvertDateToStringTZ(Date t) {
        if (t != null) {
            try {
                TimeZone tz = TimeZone.getTimeZone("UTC");
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                df.setTimeZone(tz);
                String nowAsISO = df.format(t);
                return nowAsISO;
            } catch (Exception var4) {
            }
        }

        return null;
    }

    public static Calendar toCalendar(String iso8601string) throws ParseException {
        Calendar calendar = GregorianCalendar.getInstance();
        String s = iso8601string.replace("Z", "+00:00");

        try {
            s = s.substring(0, 22) + s.substring(23);
        } catch (IndexOutOfBoundsException var4) {
            throw new ParseException("Invalid length", 0);
        }

        Date date = (new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")).parse(s);
        calendar.setTime(date);
        return calendar;
    }

    public static Date ConvertStringToTime(String s) {
        if (s != null) {
            try {
                SimpleDateFormat sdf1 = new SimpleDateFormat();
                sdf1.applyPattern("dd/MM/yyyy HH:mm:ss");
                Date date = sdf1.parse(s);
                return date;
            } catch (ParseException var3) {
                System.out.println("Exception " + var3);
            }
        }

        return null;
    }
}
