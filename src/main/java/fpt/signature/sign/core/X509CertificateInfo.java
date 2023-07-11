package fpt.signature.sign.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.Proxy.Type;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import fpt.signature.sign.ex.ConnectErrorException;
import fpt.signature.sign.ex.NotFoundURL;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class X509CertificateInfo {
    private static final Logger LOG = Logger.getLogger(X509CertificateInfo.class);
    private static final String QUERY_THROUGH_PROXY_SERVER = "QUERY_THROUGH_PROXY_SERVER";
    private static final String PROXY_IP = "PROXY_IP";
    private static final String PROXY_PORT = "PROXY_PORT";
    private static final String PROXY_USER = "PROXY_USER";
    private static final String PROXY_PASSWORD = "PROXY_PASSWORD";
    private X509Certificate x509Certificate = null;
    private X509Certificate issuer;
    private String urlOcsp = null;
    private String urlCaCert = null;
    private String urlCRL = null;
    private X509CRL crl = null;
    private Utils utils;

    public X509CertificateInfo(X509Certificate certificate) {
        this.x509Certificate = certificate;
        byte[] value1 = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
        byte[] value2 = certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (value1 != null && value1.length > 0) {
            try {
                byte[] extensionValue = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
                ASN1Sequence asn1Seq = (ASN1Sequence)X509ExtensionUtil.fromExtensionValue(extensionValue);
                Enumeration objects = asn1Seq.getObjects();

                while(objects.hasMoreElements()) {
                    ASN1Sequence obj = (ASN1Sequence)objects.nextElement();
                    DERObjectIdentifier oid = (DERObjectIdentifier)obj.getObjectAt(0);
                    DERTaggedObject location = (DERTaggedObject)obj.getObjectAt(1);
                    if (location.getTagNo() == 6) {
                        DEROctetString uri = (DEROctetString)location.getObject();
                        String str = new String(uri.getOctets());
                        if (oid.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                            this.urlOcsp = str;
                        }

                        if (oid.equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                            this.urlCaCert = str;
                        }
                    }
                }
            } catch (Exception var15) {
                this.urlCaCert = null;
                this.urlOcsp = null;
            }
        }

        if (value2 != null && value2.length > 0) {
            try {
                this.urlCRL = getCRLURL(certificate);
            } catch (CertificateParsingException var14) {
                this.urlCRL = null;
            }
        }

    }

    private static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        } else {
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
            ASN1OctetString octs = (ASN1OctetString)aIn.readObject();
            aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
            return aIn.readObject();
        }
    }

    public static String getCRLURL(X509Certificate certificate) throws CertificateParsingException {
        ASN1Primitive obj;
        try {
            obj = getExtensionValue(certificate, Extension.cRLDistributionPoints.getId());
        } catch (IOException var16) {
            obj = null;
        }

        if (obj == null) {
            return null;
        } else {
            CRLDistPoint dist = CRLDistPoint.getInstance(obj);
            DistributionPoint[] dists = dist.getDistributionPoints();
            DistributionPoint[] var4 = dists;
            int var5 = dists.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                DistributionPoint p = var4[var6];
                DistributionPointName distributionPointName = p.getDistributionPoint();
                if (0 == distributionPointName.getType()) {
                    GeneralNames generalNames = (GeneralNames)distributionPointName.getName();
                    GeneralName[] names = generalNames.getNames();
                    GeneralName[] var11 = names;
                    int var12 = names.length;

                    for(int var13 = 0; var13 < var12; ++var13) {
                        GeneralName name = var11[var13];
                        if (name.getTagNo() == 6) {
                            DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject)name.toASN1Primitive(), false);
                            return derStr.getString();
                        }
                    }
                }
            }

            return null;
        }
    }

    public String getIssuerName() {
        return this.x509Certificate.getIssuerDN().getName();
    }

    public X509Certificate getIssuer() throws NotFoundURL, ConnectErrorException {
        if (this.urlCaCert == null) {
            return null;
        } else {
            X509Certificate cert = null;

            try {
                System.out.println("Start query Issuer certificate at " + this.urlCaCert);

                InputStream inStream = queryUrlConnection(this.urlCaCert);
                if(this.urlCaCert.toLowerCase().endsWith(".p7b")){
                    cert = readCertificatesIssuerFromPKCS7(IOUtils.toByteArray(inStream));
                    System.out.println("Isser in File p7b :  " + cert.getSubjectDN().getName());
                }else{
                    CertificateFactory factory = CertificateFactory.getInstance("X509");
                    cert = (X509Certificate)factory.generateCertificate(inStream);
                }

            } catch (CertificateException var4) {
                var4.printStackTrace();
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, var4.getMessage());
            } catch (IOException ex) {
                ex.printStackTrace();
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                ex.printStackTrace();
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, null, ex);
            }

            return cert;
        }
    }

    public static final X509Certificate readCertificatesIssuerFromPKCS7(byte[] binaryPKCS7Store) throws Exception
    {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(binaryPKCS7Store);)
        {
            X509Certificate cert = null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<?> c = cf.generateCertificates(bais);


            if (c.isEmpty())
            {
                // If there are now certificates found, the p7b file is probably not in binary format.
                // It may be in base64 format.
                // The generateCertificates method only understands raw data.
            }
            else
            {

                Iterator<?> i = c.iterator();

                while (i.hasNext())
                {
                    X509Certificate ce = (X509Certificate)i.next();
                    LOG.info("cert:  " + ce.getSubjectDN().getName());
                    if(!Utils.IsSelfCert(ce)){
                        return ce;
                    }
                }
            }
            return null;
        }
    }

    public String getUrlCaCert() {
        return this.urlCaCert;
    }

    public void setUrlCaCert(String urlCaCert) {
        this.urlCaCert = urlCaCert;
    }

    public String getUrlOcsp() {
        return this.urlOcsp;
    }

    public void setUrlOcsp(String urlOcsp) {
        this.urlOcsp = urlOcsp;
    }

    public X509Certificate getX509Certificate() {
        return this.x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    public String getUrlCrl() {
        return this.urlCRL;
    }

    public void setUrlCrl(String urlCrl) {
        this.urlCRL = urlCrl;
    }

    public X509CRL getCrl() throws ConnectErrorException, NotFoundURL {
        if (this.urlCRL == null) {
            throw new NotFoundURL("Khong tim thay duong dan toi CRL Store tren Server");
        } else {
            try {
                System.setProperty("com.sun.security.enableCRLDP", "true");
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                LOG.info("Start query CRL at " + this.urlCRL);
                InputStream in = queryUrlConnection(this.urlCRL);
                if (in == null) {
                    this.crl = null;
                }

                this.crl = (X509CRL)cf.generateCRL(in);
                in.close();
            } catch (CRLException var3) {
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, (String)null, var3);
            } catch (IOException var4) {
                throw new ConnectErrorException("Ket noi mang bi loi !!!");
            } catch (CertificateException var5) {
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, (String)null, var5);
            }

            return this.crl;
        }
    }

    public static InputStream queryUrlConnection(String urlValue) {
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
        } catch (Exception var15) {
            System.out.println("Cannot read PROXY envirollment variables" +  var15.getMessage());
            var15.printStackTrace();
        }

        confUseProxy = null;

        URL url;
        try {
            url = new URL(urlValue);
        } catch (MalformedURLException var14) {
            System.out.println("Url is malformed" + var14.getMessage());
            var14.printStackTrace();
            return null;
        }

        HttpURLConnection con = null;
        if (useProxy) {
            LOG.info("Query through proxy at " + proxyIp + ":" + proxyPort);
            if (proxyUser != null && !"".equals(proxyUser) && proxyPass != null && !"".equals(proxyPass)) {
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
            } catch (Exception var13) {
                System.out.println("Cannot create url connection" + var13.getMessage());
                var13.printStackTrace();
            }
        } else {
            LOG.info("Query without proxy");

            try {
                con = (HttpURLConnection)url.openConnection();
            } catch (Exception var12) {
                System.out.println("Cannot create url connection" + var12.getMessage());
                var12.printStackTrace();
            }
        }

        if (con == null) {
            return null;
        } else {
            try {
                con.setConnectTimeout(300);
                if (con.getResponseCode() != 200) {
                    System.out.println("Query not complete. Received error code=" + con.getResponseCode() + ". " + con.getResponseMessage());
                }
            } catch (IOException var16) {
                java.util.logging.Logger.getLogger(X509CertificateInfo.class.getName()).log(Level.SEVERE, var16.getMessage() + " at X509CertificateInfo[329]");
                return null;
            }

            try {
                InputStream in = con.getInputStream();
                LOG.info("Query complete.");
                return in;
            } catch (Exception var11) {
                System.out.println("Cannot connect to host: " + var11.getMessage());
                var11.printStackTrace();
                return null;
            }
        }
    }

    public void setCrl(X509CRL crl) {
        this.crl = crl;
    }
}
