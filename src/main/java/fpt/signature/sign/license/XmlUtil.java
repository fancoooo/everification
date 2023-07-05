package fpt.signature.sign.license;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperties;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperty;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLObject;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XmlUtil {
    private static final Logger LOG = Logger.getLogger(XmlUtil.class);
    private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    public static Document loadXmlDocument(byte[] data) throws SignServerSignaturesException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
            return doc;
        } catch (ParserConfigurationException var3) {
            LOG.error("ParserConfigurationException => " + var3.getMessage(), var3);
            throw new SignServerSignaturesException(var3.getMessage(), var3);
        } catch (SAXException var4) {
            LOG.error("SAXException => " + var4.getMessage(), var4);
            throw new SignServerSignaturesException(var4.getMessage(), var4);
        } catch (IOException var5) {
            LOG.error("IOException => " + var5.getMessage(), var5);
            throw new SignServerSignaturesException(var5.getMessage(), var5);
        }
    }

    public static Certificate[] getCertificateChain(byte[] signedData) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(signedData));
            NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider)Class.forName(providerName).newInstance());
            DOMValidateContext valContext = new DOMValidateContext(new XmlUtil.X509KeySelector(), nl.item(0));
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            return getCertificateChain(signature);
        } catch (ParserConfigurationException var8) {
            LOG.error("ParserConfigurationException => " + var8.getMessage());
        } catch (SAXException var9) {
            LOG.error("SAXException => " + var9.getMessage());
        } catch (IOException var10) {
            LOG.error("IOException => " + var10.getMessage());
        } catch (InstantiationException var11) {
            LOG.error("InstantiationException => " + var11.getMessage());
        } catch (IllegalAccessException var12) {
            LOG.error("IllegalAccessException => " + var12.getMessage());
        } catch (ClassNotFoundException var13) {
            LOG.error("ClassNotFoundException => " + var13.getMessage());
        } catch (MarshalException var14) {
            LOG.error("MarshalException => " + var14.getMessage());
        }

        return null;
    }

    public static Certificate[] getCertificateChain(XMLSignature signature) {
        List<Certificate> result = new ArrayList();
        Iterator ki = signature.getKeyInfo().getContent().iterator();

        while(true) {
            XMLStructure info;
            do {
                if (!ki.hasNext()) {
                    Certificate[] certChain = new Certificate[result.size()];
                    certChain = (Certificate[])result.toArray(certChain);
                    return certChain;
                }

                info = (XMLStructure)ki.next();
            } while(!(info instanceof X509Data));

            X509Data x509Data = (X509Data)info;
            Iterator xi = x509Data.getContent().iterator();

            while(xi.hasNext()) {
                Object o = xi.next();
                if (o instanceof Certificate) {
                    result.add((Certificate)o);
                }
            }
        }
    }

    public static PublicKey getPublicKey(XMLSignature signature) {
        List<?> list = signature.getKeyInfo().getContent();
        PublicKey result = null;

        for(int i = 0; i < list.size(); ++i) {
            XMLStructure xmlStructure = (XMLStructure)list.get(i);
            if (xmlStructure instanceof KeyValue) {
                try {
                    result = ((KeyValue)xmlStructure).getPublicKey();
                    break;
                } catch (KeyException var6) {
                    LOG.error("KEY EXCEPTION " + var6.getMessage());
                }
            }
        }

        return result;
    }

    public static Date getSigningTime(XMLSignature signature) {
        List<?> listReferences = signature.getObjects();
        String dateTime = "";
        Iterator var3 = listReferences.iterator();

        label79:
        while(true) {
            Object o;
            do {
                if (!var3.hasNext()) {
                    var3 = null;

                    Date signTime;
                    try {
                        signTime = new Date(dateTime);
                    } catch (Exception var20) {
                        signTime = new Date();
                    }

                    return signTime;
                }

                o = var3.next();
            } while(!(o instanceof DOMXMLObject));

            DOMXMLObject dom = (DOMXMLObject)o;
            List<?> list = dom.getContent();
            Iterator var7 = list.iterator();

            label77:
            while(true) {
                Object o1;
                do {
                    if (!var7.hasNext()) {
                        continue label79;
                    }

                    o1 = var7.next();
                } while(!(o1 instanceof DOMSignatureProperties));

                DOMSignatureProperties properties = (DOMSignatureProperties)o1;
                List<?> props = properties.getProperties();
                Iterator var11 = props.iterator();

                label75:
                while(true) {
                    Object o2;
                    do {
                        if (!var11.hasNext()) {
                            continue label77;
                        }

                        o2 = var11.next();
                    } while(!(o2 instanceof DOMSignatureProperty));

                    DOMSignatureProperty prop = (DOMSignatureProperty)o2;
                    List<?> listProp = prop.getContent();
                    Iterator var15 = listProp.iterator();

                    while(true) {
                        Node node;
                        do {
                            Object o3;
                            do {
                                if (!var15.hasNext()) {
                                    continue label75;
                                }

                                o3 = var15.next();
                            } while(!(o3 instanceof DOMStructure));

                            DOMStructure structure = (DOMStructure)o3;
                            node = structure.getNode();
                            if ("DateTimeStamp".equals(node.getNodeName())) {
                                Long timeValue = new Long(node.getFirstChild().getNodeValue());
                                return new Date(timeValue);
                            }
                        } while(!"DATE".equalsIgnoreCase(node.getNodeName()) && !"TIME".equalsIgnoreCase(node.getNodeName()) && !"TIMEZONE".equalsIgnoreCase(node.getNodeName()));

                        String timeValue = node.getFirstChild().getNodeValue();
                        dateTime = dateTime + timeValue + " ";
                    }
                }
            }
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return this.pk;
        }
    }

    public static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            } else {
                SignatureMethod sm = (SignatureMethod)method;
                List<?> list = keyInfo.getContent();

                for(int i = 0; i < list.size(); ++i) {
                    XMLStructure xmlStructure = (XMLStructure)list.get(i);
                    if (xmlStructure instanceof KeyValue) {
                        PublicKey pk = null;

                        try {
                            pk = ((KeyValue)xmlStructure).getPublicKey();
                        } catch (KeyException var11) {
                            throw new KeySelectorException(var11);
                        }

                        if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                            return new XmlUtil.SimpleKeySelectorResult(pk);
                        }
                    }
                }

                throw new KeySelectorException("Element KeyValue not found!");
            }
        }

        static boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#dsa-sha1")) {
                return true;
            } else if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#rsa-sha1")) {
                return true;
            } else {
                return algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            }
        }
    }

    public static class X509KeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            Iterator ki = keyInfo.getContent().iterator();

            while(true) {
                XMLStructure info;
                do {
                    if (!ki.hasNext()) {
                        throw new KeySelectorException("No key found!");
                    }

                    info = (XMLStructure)ki.next();
                } while(!(info instanceof X509Data));

                X509Data x509Data = (X509Data)info;
                Iterator xi = x509Data.getContent().iterator();

                while(xi.hasNext()) {
                    Object o = xi.next();
                    if (o instanceof X509Certificate) {
                        final PublicKey key = ((X509Certificate)o).getPublicKey();
                        if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                            return new KeySelectorResult() {
                                public Key getKey() {
                                    return key;
                                }
                            };
                        }
                    }
                }
            }
        }

        static boolean algEquals(String algURI, String algName) {
            return algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#dsa-sha1") || algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#rsa-sha1") || algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        }
    }

    public static class ExternalKeySelector extends KeySelector {
        private List<X509Certificate> signerCerts;

        public ExternalKeySelector(List<X509Certificate> certs) {
            this.signerCerts = certs;
        }

        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            Iterator<?> ki = keyInfo.getContent().iterator();
            BigInteger serialValue = null;

            while(true) {
                while(true) {
                    DOMStructure ds;
                    do {
                        do {
                            XMLStructure info;
                            do {
                                if (!ki.hasNext()) {
                                    if (serialValue == null) {
                                        throw new KeySelectorException("No key found!");
                                    }

                                    Iterator var12 = this.signerCerts.iterator();

                                    while(var12.hasNext()) {
                                        X509Certificate cert = (X509Certificate)var12.next();
                                        if (cert != null && serialValue.compareTo(cert.getSerialNumber()) == 0) {
                                            final PublicKey key = cert.getPublicKey();
                                            if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                                                return new KeySelectorResult() {
                                                    public Key getKey() {
                                                        return key;
                                                    }
                                                };
                                            }
                                        }
                                    }

                                    throw new KeySelectorException("No key found!");
                                }

                                info = (XMLStructure)ki.next();
                            } while(!(info instanceof DOMStructure));

                            ds = (DOMStructure)info;
                        } while(ds.getNode() == null);
                    } while(ds.getNode().getChildNodes() == null);

                    NodeList childNodes = ds.getNode().getChildNodes();

                    for(int i = 0; i < childNodes.getLength(); ++i) {
                        Node item = childNodes.item(i);
                        if ("X509SerialNumber".equals(item.getNodeName())) {
                            serialValue = new BigInteger(item.getTextContent(), 10);
                            XmlUtil.LOG.info("Found signer with serial=" + serialValue);
                            break;
                        }
                    }
                }
            }
        }

        static boolean algEquals(String algURI, String algName) {
            return algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#dsa-sha1") || algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#rsa-sha1") || algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        }
    }
}
