package fpt.signature.sign.license;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.jcp.xml.dsig.internal.dom.DOMReference;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XmlValidator {
    private static final Logger LOG = Logger.getLogger(XmlValidator.class);
    private static final String SIGNATURE_TAG_NAME = "Signature";
    private String singleSignError = "";

    public ValidationResponseData verify(byte[] data) throws SignServerSignaturesException {
        ValidationData signedData = new ValidationData(data, (List)null, 0);
        return this.verify(signedData);
    }

    public ValidationResponseData verify(byte[] data, List<X509Certificate> trustAnchor, int revokeMethod) throws SignServerSignaturesException {
        List<Certificate> anchors = new ArrayList();
        Iterator var5 = trustAnchor.iterator();

        while(var5.hasNext()) {
            X509Certificate cert = (X509Certificate)var5.next();
            anchors.add(cert);
        }

        ValidationData signedData = new ValidationData(data, anchors, revokeMethod);
        return this.verify(signedData);
    }

    public ValidationResponseData verify(ValidationData signedData) throws SignServerSignaturesException {
        Security.addProvider(new BouncyCastleProvider());
        ValidationResponseData response = new ValidationResponseData();
        if (signedData != null && signedData.getSignedData() != null) {
            int certValidateMethod = signedData.getCertVerifyMethod();
            if (certValidateMethod < 0) {
                certValidateMethod = -1;
            }

            Document doc = null;

            try {
                doc = XmlUtil.loadXmlDocument(signedData.getSignedData());
            } catch (SignServerSignaturesException var17) {
                response.setMessage("Cannot load xml document (" + var17.getMessage() + ")");
                response.setResutCode(-1);
                return response;
            }

            DocumentBuilderFactory dbf = null;

            try {
                dbf = DocumentBuilderFactory.newInstance();
                dbf.setIgnoringElementContentWhitespace(true);
                dbf.setNamespaceAware(true);
            } catch (Exception var16) {
                response.setMessage("Cannot init DocumentBuilderFactory instance (" + var16.getMessage() + ")");
                response.setResutCode(-1);
                return response;
            }

            String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
            if (providerName == null || "".equals(providerName)) {
                LOG.warn("No jsr105Provider found in your system");
            }

            XMLSignatureFactory fac = null;

            try {
                fac = XMLSignatureFactory.getInstance("DOM", (Provider)Class.forName(providerName).newInstance());
            } catch (InstantiationException var13) {
                LOG.error("InstantiationException", var13);
                response.setMessage("Cannot init XMLSignatureFactory instance (" + var13.getMessage() + ")");
            } catch (IllegalAccessException var14) {
                LOG.error("IllegalAccessException", var14);
                response.setMessage("Cannot init XMLSignatureFactory instance (" + var14.getMessage() + ")");
            } catch (ClassNotFoundException var15) {
                LOG.error("ClassNotFoundException", var15);
                response.setMessage("Cannot init XMLSignatureFactory instance (" + var15.getMessage() + ")");
            }

            if (fac == null) {
                response.setResutCode(-1);
                return response;
            } else {
                NodeList sigNodeList = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
                if (sigNodeList != null && sigNodeList.getLength() != 0) {
                    int signCount = sigNodeList.getLength();

                    for(int index = 0; index < signCount; ++index) {
                        Node signNode = sigNodeList.item(index);
                        if (signNode != null) {
                            int singleSignResult = this.verifySingleSignature(signNode, fac, doc, certValidateMethod);
                            if (0 != singleSignResult) {
                                response.setMessage(this.singleSignError);
                                response.setResutCode(singleSignResult);
                                return response;
                            }
                        }
                    }

                    response.setMessage("All signatures in document are valid");
                    response.setResutCode(0);
                    return response;
                } else {
                    response.setMessage("No signature tag in document found.");
                    response.setResutCode(-1);
                    return response;
                }
            }
        } else {
            LOG.error("No signed data found.");
            response.setMessage("No signed data parameter.");
            response.setResutCode(-1);
            return response;
        }
    }

    private int verifySingleSignature(Node signNode, XMLSignatureFactory fac, Document doc, int certValidateMethod) {
        Security.addProvider(new BouncyCastleProvider());
        XMLSignature signature = null;
        DOMValidateContext valContext = null;

        try {
            valContext = new DOMValidateContext(new XmlUtil.X509KeySelector(), signNode);
            signature = fac.unmarshalXMLSignature(valContext);
        } catch (Exception var16) {
            this.singleSignError = "One of signatures invalid (" + var16.getMessage() + ")";
            return -1;
        }

        DOMReference reference = (DOMReference)signature.getSignedInfo().getReferences().get(0);
        if (reference.getURI().contains("#")) {
            String id = reference.getURI().replace("#", "");
            String expression = "//*[contains(@id,'" + id + "') or contains(@iD ,'" + id + "') or contains(@Id ,'" + id + "') or contains(@ID ,'" + id + "')]";
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();

            try {
                NodeList nodeList = (NodeList)xpath.evaluate(expression, doc, XPathConstants.NODESET);

                for(int j = 0; j < nodeList.getLength(); ++j) {
                    Element e = (Element)nodeList.item(j);
                    if (e.getAttribute("ID") != null && !e.getAttribute("ID").equals("")) {
                        e.setIdAttribute("ID", true);
                    }

                    if (e.getAttribute("id") != null && !e.getAttribute("id").equals("")) {
                        e.setIdAttribute("id", true);
                    }

                    if (e.getAttribute("iD") != null && !e.getAttribute("iD").equals("")) {
                        e.setIdAttribute("iD", true);
                    }

                    if (e.getAttribute("Id") != null && !e.getAttribute("Id").equals("")) {
                        e.setIdAttribute("Id", true);
                    }
                }
            } catch (XPathExpressionException var17) {
                LOG.error("XPathExpressionException", var17);
                this.singleSignError = "One of signatures invalid (" + var17.getMessage() + ")";
            }
        }

        boolean res = false;

        try {
            res = signature.validate(valContext);
        } catch (XMLSignatureException var15) {
            LOG.error("XMLSignatureException", var15);
            return -1;
        }

        if (res) {
            Date signingTime = XmlUtil.getSigningTime(signature);
            Certificate[] certchain = XmlUtil.getCertificateChain(signature);
            X509Certificate signerCert = null;
            if (certchain != null && certchain.length > 0) {
                signerCert = (X509Certificate)certchain[0];
            }

            int certValid = this.verifySigner(signerCert);
            return certValid;
        } else {
            this.singleSignError = "One of signatures invalid (Valcontext not valid)";
            return -1;
        }
    }

    private int verifySigner(X509Certificate signerCert) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            byte[] signerCertBytes = Base64.decode("MIIC9TCCAd2gAwIBAgIEXwwFZDANBgkqhkiG9w0BAQsFADApMQswCQYDVQQGEwJWTjEaMBgGA1UEAwwRRVNJR05BVFVSRSBTRVJWRVIwHhcNMjAwNzEzMDY1NTMyWhcNMzAwNzEzMDY1NTMyWjApMQswCQYDVQQGEwJWTjEaMBgGA1UEAwwRRVNJR05BVFVSRSBTRVJWRVIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC665OAwWfHCdwhoL6tXiFJBom93Nunvs9hXc4QqMMF/+YJgajlf3O7YQ9CwjW7NrT2QPlR3uhngicQpuc8jdmJKAf7rIltPYursRsKCMtynHgwAGWeKAHU4LtUokq298C1mIF0QnI78Osfzpl79qgpRDU6Rv/0Q4/4kwMSApWk4B5A0ooTTsz6oCKxJUBy8Wu6BjyRevMl6PtAkTVY+16OXEm+2SUZ5yG9aNyDshQJbFFeQMkzVrhrR0T0sJ3+PQ5CK8PteR+TcQpSpdK4O8pYbl+r62esQJZQtXkMz4iUcUJphWSPzVYbM5NeEVs5NJusE0rqUdXn+mWW10GtZ/iRAgMBAAGjJTAjMBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdDwQFAwMH0YAwDQYJKoZIhvcNAQELBQADggEBABIGYDeH350SBMDiiPDTKS6P2rK3UndYCtJRnDxvtp1MaAQblYRqxY8V8OIEmLyJEhzCNn0jO3S5esIG1Ql5OepJKuxkrT8sMHy/YuvSk7KjDgVf+GGDt112VmZZKaTBDgKHo4bha5463x5+pqD6/GKNcSMdIMH7sndMYDEKPf9Ueionnud3V7E4Zkilf2HNUkBc+KsI3TrMLUhA91IYgn9C2iE3qn/BEmRydROA71vkKZzARNXQ7yKvFo1pTazEKS9uGKpzUE8fV+58RGXuhXwilyWw//+D/X6f2f1nwc/7pOepsBszeopK5aNZqCCINwGO711lxFVvUdzraY0L+wQ=");
            ByteArrayInputStream certStream = new ByteArrayInputStream(signerCertBytes);
            Certificate signerInner = factory.generateCertificate(certStream);
            X509Certificate inner = (X509Certificate)signerInner;
            if (signerCert.equals(inner)) {
                return 0;
            }
        } catch (CertificateException var7) {
            java.util.logging.Logger.getLogger(XmlValidator.class.getName()).log(Level.SEVERE, (String)null, var7);
        }

        return -1;
    }
}