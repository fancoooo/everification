package fpt.signature.sign.everification.core;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import fpt.signature.sign.everification.objects.*;
import fpt.signature.sign.security.ApplicationContextProvider;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.MobileIDX500NameStyle;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XAdESVerification {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.core.XAdESVerification.class);

    private static final String DEFAULT_SIGNINGTIME_TAG_NAME = "SigningTime";

    private static final String DEFAULT_SIGNINGTIME_FORMAT = "yyyy-MM-dd'T'hh:mm:ss";

    private String lang;

    private String entityBillCode;

    private List<X509Certificate> registeredCerts;

    private String serialNumber;

    private boolean signerInformation;

    private boolean certificatesInformation;

    private boolean registeredConstraint;

    private boolean signedDataRequired;

    private String signingTimeTag;

    private String signingTimeFormat;

    private boolean officeDocument;

    private int acceptableCrlDuration;

    public XAdESVerification() {
        this.lang = "en";
        this.signerInformation = true;
    }


    public XAdESVerification(String lang, String entityBillCode, List<X509Certificate> registeredCerts, String serialNumber) {
        this.lang = lang;
        this.entityBillCode = entityBillCode;
        this.registeredCerts = registeredCerts;
        this.serialNumber = serialNumber;
    }

    public VerificationInternalResponse verify(byte[] document, String billCode) {
        Document doc = null;
        ByteArrayInputStream bais = new ByteArrayInputStream(document);
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
        try {
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            doc = docBuilder.parse(bais);
        } catch (Exception e) {
            LOG.error("Cannot read XML document. Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(2010, "Cannot read XML document", billCode);
        }
        NodeList nodeList = null;
        XPathExpression expr = null;
        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
            expr = xpath.compile("//*[@Id]");
            nodeList = (NodeList)expr.evaluate(doc, XPathConstants.NODESET);
        } catch (Exception e) {
            LOG.error("Cannot analyze signature namespace (id or Id). Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(2003, "Cannot analyze signature namespace (id or Id)", billCode);
        }
        int i;
        for (i = 0; i < nodeList.getLength(); i++) {
            Element elem = (Element)nodeList.item(i);
            elem.setIdAttributeNS(null, "Id", true);
        }
        try {
            expr = xpath.compile("//*[@id]");
            nodeList = (NodeList)expr.evaluate(doc, XPathConstants.NODESET);
        } catch (Exception e) {
            LOG.error("Cannot analyze signature namespace (id or Id). Details: " + Utils.printStackTrace(e));
            return new VerificationInternalResponse(2003, "Cannot analyze signature namespace (id or Id)", billCode);
        }
        for (i = 0; i < nodeList.getLength(); i++) {
            Element elem = (Element)nodeList.item(i);
            elem.setIdAttributeNS(null, "id", true);
        }
        NodeList sigList = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        if (sigList.getLength() == 0)
            return new VerificationInternalResponse(0);
        List<ValidityResult> validityResults = new ArrayList<>();
        for (int j = 0; j < sigList.getLength(); j++) {
            X509Certificate signerCertificate = null;
            List<X509Certificate> x509CertList = new ArrayList<>();
            boolean integrity = false;
            boolean finalResult = true;
            Boolean registeredChecks = null;
            TSAChecks tsaChecks = null;
            Date signingTime = null;
            String signedData = null;
            String signatureID = null;
            String algorithm = null;
            ValidityResult validityResult = new ValidityResult();
            VerificationDetails verificationDetails = new VerificationDetails();
            KeyInfoKeySelector keySelector = new KeyInfoKeySelector(this);
            DOMValidateContext valContext = new DOMValidateContext((KeySelector)keySelector, sigList.item(j));
            XMLSignature signature = null;
            try {
                    signature = fac.unmarshalXMLSignature(valContext);
                integrity = signature.validate(valContext);
            } catch (Exception e) {
                LOG.error("Cannot validate signature due to MarshalException/XMLSignatureException. Details: " + Utils.printStackTrace(e));
                verificationDetails.setIntegrity(Boolean.FALSE);
                validityResult.setVerificationDetails(verificationDetails);
                validityResults.add(validityResult);
            }
            Element sigElem = (Element)sigList.item(j);
            if (sigElem.hasAttribute("Id")) {
                signatureID = sigElem.getAttribute("Id");
            } else if (sigElem.hasAttribute("id")) {
                signatureID = sigElem.getAttribute("id");
            } else {
                signatureID = "";
            }
            algorithm = getAlgorithm(sigList.item(j));
            signerCertificate = keySelector.getCertificate();
            x509CertList = Arrays.asList(keySelector.getCertChain());
            List<TimeStampToken> timeStampTokenList = new ArrayList<>();
            getTimestampToken(sigList.item(j), timeStampTokenList);
            if (!timeStampTokenList.isEmpty()) {
                validityResult.setTimestampEmbedded(true);
                TimeStampToken timeStampToken = timeStampTokenList.get(0);
                signingTime = timeStampToken.getTimeStampInfo().getGenTime();
                Store storeTt = timeStampToken.getCertificates();
                Collection collTt = storeTt.getMatches((Selector)timeStampToken.getSID());
                Collection<? extends X509CertificateHolder> tsaX509CertCollection = storeTt.getMatches(null);
                List<X509CertificateHolder> tsaHolders = new ArrayList<>();
                tsaHolders.addAll(tsaX509CertCollection);
                List<X509Certificate> tsaX509CertList = new ArrayList<>();
                JcaX509CertificateConverter tsaX509CertificateConverter = (new JcaX509CertificateConverter()).setProvider((Provider)new BouncyCastleProvider());
                for (X509CertificateHolder holder : tsaHolders) {
                    try {
                        tsaX509CertList.add(tsaX509CertificateConverter.getCertificate(holder));
                    } catch (CertificateException e) {
                        LOG.error("Cannot get X509Certificate from X509CertificateHolder. Details: " + Utils.printStackTrace(e));
                        verificationDetails.setIntegrity(Boolean.FALSE);
                        validityResult.setVerificationDetails(verificationDetails);
                        validityResults.add(validityResult);
                    }
                }
                try {
                    tsaX509CertList = Crypto.sortX509Chain(tsaX509CertList);
                } catch (Exception e) {
                    LOG.error("Error while sorting X509 certificate chain. Details: " + Utils.printStackTrace(e));
                    verificationDetails.setIntegrity(Boolean.FALSE);
                    validityResult.setVerificationDetails(verificationDetails);
                    validityResults.add(validityResult);
                }
                Iterator<X509CertificateHolder> certIt2 = collTt.iterator();
                X509CertificateHolder cert2 = certIt2.next();
                tsaChecks = new TSAChecks();
                boolean tsaIntegrity = false;
                boolean tsaCertPathValidation = false;
                boolean tsaTrustedCertificate = false;
                try {
                    timeStampToken.validate((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert2));
                    tsaIntegrity = true;
                } catch (Exception e) {
                    LOG.error("Failed to verify timestamp signature. Details: " + Utils.printStackTrace(e));
                }

                tsaCertPathValidation = new CertPathValidation().validate(tsaX509CertList);
                tsaTrustedCertificate = new TrustedCertificateChecks().validate(tsaX509CertList).isValid();
                RevocationChecks tsaRevocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.valueOf(true), this.acceptableCrlDuration)).validate(tsaX509CertList.get(0), signingTime);
                finalResult = tsaCertPathValidation && tsaTrustedCertificate && tsaRevocationChecks.isSuccess();
                tsaChecks.setIntegrity(tsaIntegrity);
                tsaChecks.setCertPathValidation(tsaCertPathValidation);
                tsaChecks.setTrustedCertificate(tsaTrustedCertificate);
                tsaChecks.setRevocationChecks(tsaRevocationChecks);
            } else {
                signingTime = getSigningTime(sigList.item(j),
                        Utils.isNullOrEmpty(this.signingTimeTag) ? "SigningTime" : this.signingTimeTag,
                        Utils.isNullOrEmpty(this.signingTimeFormat) ? "yyyy-MM-dd'T'hh:mm:ss" : this.signingTimeFormat);
                if (this.officeDocument)
                    try {
                        signingTime = Utils.convertToUTC(signingTime);
                    } catch (ParseException ex) {
                        LOG.error("Cannot convert signing time to UTC");
                        return new VerificationInternalResponse(2003);
                    }
            }
            boolean certPathValidation = new CertPathValidation().validate(x509CertList);
            Result trustedCheckResult = new TrustedCertificateChecks().validate(x509CertList);
            boolean trustedCertificate = trustedCheckResult.isValid();
            RevocationChecks revocationChecks = (new RevocationStatusChecks(this.lang, this.entityBillCode, null, null, Boolean.valueOf(true), this.acceptableCrlDuration)).validate(x509CertList.get(0), signingTime);
            ValidityChecks validityChecks = (new ValidityStatusChecks(this.lang)).validate(x509CertList.get(0), signingTime);
            if (this.registeredCerts != null) {
                registeredChecks = Boolean.valueOf(this.registeredCerts.contains(x509CertList.get(0)));
            } else if (this.registeredConstraint) {
                registeredChecks = Boolean.FALSE;
            }
            if (!Utils.isNullOrEmpty(this.serialNumber))
                registeredChecks = this.serialNumber.compareToIgnoreCase(DatatypeConverter.printHexBinary(((X509Certificate) x509CertList.get(0)).getSerialNumber().toByteArray())) == 0;
            verificationDetails.setIntegrity(integrity);
            verificationDetails.setCertPathValidation(certPathValidation);
            verificationDetails.setTrustedCertificate(trustedCertificate);
            verificationDetails.setRegisteredChecks(registeredChecks);
            verificationDetails.setRevocationChecks(revocationChecks);
            verificationDetails.setValidityChecks(validityChecks);
            verificationDetails.setValidity(validityChecks.isSuccess());
            if (registeredChecks == null) {
                finalResult = (finalResult && integrity && certPathValidation && trustedCertificate && revocationChecks.isSuccess() && validityChecks.isSuccess());
            } else {
                finalResult = (finalResult && integrity && certPathValidation && trustedCertificate && revocationChecks.isSuccess() && validityChecks.isSuccess() && registeredChecks.booleanValue());
            }
            validityResult.setSigingForm("XML-DSig");
            validityResult.setSignatureID(signatureID);
            validityResult.setAlgorithm(algorithm);
            validityResult.setSigningTime(signingTime);
            if (this.signedDataRequired)
                validityResult.setSignedData(signedData);
            validityResult.setSuccess(finalResult);
            validityResult.setVerificationDetails(verificationDetails);
            validityResult.setTsa(tsaChecks);
            if (this.signerInformation) {
                X500Name x500SubjectName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getSubjectDN().toString());
                String subjectDn = x500SubjectName.toString();
                X500Name x500IssuerName = new X500Name((X500NameStyle)new MobileIDX500NameStyle(), signerCertificate.getIssuerDN().toString());
                String issuerDn = x500IssuerName.toString();
                String thumbprint = null;
                try {
                    thumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getEncoded(), "SHA-1")).toLowerCase();
                } catch (CertificateEncodingException e) {
                    LOG.error("Cannot calculate certificate thumbprint. Details: " + Utils.printStackTrace(e));
                }
                String serialNumber = DatatypeConverter.printHexBinary(signerCertificate.getSerialNumber().toByteArray()).toLowerCase();
                String keyHash = DatatypeConverter.printHexBinary(Crypto.hashData(signerCertificate.getPublicKey().getEncoded(), "SHA-1")).toLowerCase();
                validityResult.setSubject(subjectDn);
                validityResult.setSigner_cn(CertificatePolicy.getCommonName(subjectDn));
                validityResult.setIssuer(issuerDn);
                validityResult.setIssuer_cn(CertificatePolicy.getCommonName(issuerDn));
                validityResult.setThumbprint(thumbprint);
                validityResult.setSerialNumber(serialNumber);
                validityResult.setKeyHash(keyHash);
                validityResult.setValidFrom(signerCertificate.getNotBefore());
                validityResult.setValidTo(signerCertificate.getNotAfter());
                if (x509CertList.size() == 1)
                    x509CertList = new CertPathValidation().buildPath(signerCertificate);
                if (x509CertList.size() > 1) {
                    String issuerThumbprint = null;
                    String issuerSerialNumber = null;
                    String issuerKeyIdentifier = null;
                    String rootCAKeyIdentifier = null;
                    try {
                        issuerThumbprint = DatatypeConverter.printHexBinary(Crypto.hashData(((X509Certificate)x509CertList.get(1)).getEncoded(), "SHA-1")).toLowerCase();
                        issuerSerialNumber = DatatypeConverter.printHexBinary(((X509Certificate)x509CertList.get(1)).getSerialNumber().toByteArray()).toLowerCase();
                        issuerKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(1));
                        if (Crypto.isRootCACertificate(x509CertList.get(x509CertList.size() - 1))) {
                            rootCAKeyIdentifier = Crypto.getSubjectKeyIdentifier(x509CertList.get(x509CertList.size() - 1));
                        } else  {
                            LOG.error("Bottom certificate in chain is not ROOT CA --> rootCAKeyIdentifier = NULL");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    validityResult.setIssuerSerialNumber(issuerSerialNumber);
                    validityResult.setIssuerThumbprint(issuerThumbprint);
                    validityResult.setIssuerKeyIdentifier(issuerKeyIdentifier);
                    validityResult.setRootCAKeyIdentifier(rootCAKeyIdentifier);
                }
            }
            if (this.certificatesInformation)
                try {
                    String certificateStr = DatatypeConverter.printBase64Binary(signerCertificate.getEncoded());
                    String[] chains = new String[x509CertList.size()];
                    List<String> l = new ArrayList<>();
                    for (X509Certificate certItem : x509CertList)
                        l.add(DatatypeConverter.printBase64Binary(certItem.getEncoded()));
                    chains = l.<String>toArray(chains);
                    validityResult.setCertificate(certificateStr);
                    validityResult.setChains(chains);
                } catch (CertificateEncodingException e) {
                    LOG.error("Cannot get certificate base64 encoded. Details: " + Utils.printStackTrace(e));
                }
            validityResults.add(validityResult);
        }
        VerificationInternalResponse verificationInternalResponse = new VerificationInternalResponse();
        verificationInternalResponse.setStatus(0);
        verificationInternalResponse.setMessage("SUCCESSFULLY");
        verificationInternalResponse.setResponse_bill_code(billCode);
        verificationInternalResponse.setValidityResults(validityResults);
        return verificationInternalResponse;
    }

    private void getTimestampToken(Node node, List<TimeStampToken> timeStampTokenList) {
        try {
            if (node.getNodeName().contains("xades:EncapsulatedTimeStamp")) {
                String value = node.getTextContent();
                TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(DatatypeConverter.parseBase64Binary(value)));
                timeStampTokenList.add(timeStampToken);
            }
            NodeList nodeList = node.getChildNodes();
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node currentNode = nodeList.item(i);
                if (currentNode.getNodeType() == 1)
                    getTimestampToken(currentNode, timeStampTokenList);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Date getSigningTime(Node node, String signTagName, String dateFormat) {
        Date signingTime = null;
        try {
            if (node.getNodeName().contains(signTagName)) {
                String value = null;
                NodeList checkChildNode = node.getChildNodes();
                if (checkChildNode.getLength() > 1) {
                    for (int j = 0; j < checkChildNode.getLength(); j++) {
                        if (checkChildNode.item(j).getNodeName().contains("Value")) {
                            value = checkChildNode.item(j).getTextContent().trim();
                            break;
                        }
                    }
                } else {
                    value = node.getTextContent().trim();
                }
                if (!Utils.isNullOrEmpty(value)) {
                    SimpleDateFormat sdf = null;
                    try {
                        sdf = new SimpleDateFormat(dateFormat);
                        signingTime = sdf.parse(value);
                        return signingTime;
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                } else {
                    return null;
                }
            }
            NodeList nodeList = node.getChildNodes();
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node currentNode = nodeList.item(i);
                if (currentNode.getNodeType() == 1) {
                    signingTime = getSigningTime(currentNode, signTagName, dateFormat);
                    if (signingTime != null)
                        break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signingTime;
    }

    private String getAlgorithm(Node signatureNode) {
        String prefix = signatureNode.getPrefix();
        if (Utils.isNullOrEmpty(prefix)) {
            prefix = "";
        } else {
            prefix = prefix + ":";
        }
        NodeList childsOfSignature = signatureNode.getChildNodes();
        for (int k1 = 0; k1 < childsOfSignature.getLength(); k1++) {
            Node currentNodeInSignature = childsOfSignature.item(k1);
            if (currentNodeInSignature.getNodeType() == 1 &&
                    currentNodeInSignature.getNodeName().equals(prefix + "SignedInfo")) {
                NodeList childsOfSignedInfo = currentNodeInSignature.getChildNodes();
                for (int k2 = 0; k2 < childsOfSignedInfo.getLength(); k2++) {
                    Node currentNodeInSignedInfo = childsOfSignedInfo.item(k2);
                    if (currentNodeInSignature.getNodeType() == 1 &&
                            currentNodeInSignedInfo.getNodeName().equals(prefix + "Reference")) {
                        NodeList childsOfReference = currentNodeInSignedInfo.getChildNodes();
                        for (int k3 = 0; k3 < childsOfReference.getLength(); k3++) {
                            Node currentNodeReference = childsOfReference.item(k3);
                            if (currentNodeInSignature.getNodeType() == 1 &&
                                    currentNodeReference.getNodeName().equals(prefix + "DigestMethod"))
                                return ((Element)currentNodeReference).getAttribute("Algorithm");
                        }
                    }
                }
            }
        }
        return null;
    }

    public boolean isSignerInformation() {
        return this.signerInformation;
    }

    public void setSignerInformation(boolean signerInformation) {
        this.signerInformation = signerInformation;
    }

    public boolean isCertificatesInformation() {
        return this.certificatesInformation;
    }

    public void setCertificatesInformation(boolean certificatesInformation) {
        this.certificatesInformation = certificatesInformation;
    }

    public boolean isRegisteredConstraint() {
        return this.registeredConstraint;
    }

    public void setRegisteredConstraint(boolean registeredConstraint) {
        this.registeredConstraint = registeredConstraint;
    }

    public boolean isSignedDataRequired() {
        return this.signedDataRequired;
    }

    public void setSignedDataRequired(boolean signedDataRequired) {
        this.signedDataRequired = signedDataRequired;
    }

    public String getSigningTimeTag() {
        return this.signingTimeTag;
    }

    public void setSigningTimeTag(String signingTimeTag) {
        this.signingTimeTag = signingTimeTag;
    }

    public String getSigningTimeFormat() {
        return this.signingTimeFormat;
    }

    public void setSigningTimeFormat(String signingTimeFormat) {
        this.signingTimeFormat = signingTimeFormat;
    }

    public void setOfficeDocument(boolean officeDocument) {
        this.officeDocument = officeDocument;
    }

    public int getAcceptableCrlDuration() {
        return this.acceptableCrlDuration;
    }

    public void setAcceptableCrlDuration(int acceptableCrlDuration) {
        this.acceptableCrlDuration = acceptableCrlDuration;
    }

    class KeyInfoKeySelector extends KeySelector implements KeySelectorResult {
        private X509Certificate certificate;
        private X509Certificate[] certChain;
        // $FF: synthetic field
        final XAdESVerification this$0;

        private KeyInfoKeySelector(XAdESVerification var1) {
            this.this$0 = var1;
        }

        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            ArrayList certList = new ArrayList();
            if (null == keyInfo) {
                throw new KeySelectorException("no ds:KeyInfo present");
            } else {
                List<XMLStructure> keyInfoContent = keyInfo.getContent();
                this.certificate = null;
                Iterator var7 = keyInfoContent.iterator();

                do {
                    XMLStructure keyInfoStructure;
                    do {
                        if (!var7.hasNext()) {
                            throw new KeySelectorException("No key found!");
                        }

                        keyInfoStructure = (XMLStructure)var7.next();
                    } while(!(keyInfoStructure instanceof X509Data));

                    X509Data x509Data = (X509Data)keyInfoStructure;
                    List x509DataList = x509Data.getContent();
                    Iterator var11 = x509DataList.iterator();

                    while(var11.hasNext()) {
                        Object x509DataObject = var11.next();
                        if (x509DataObject instanceof X509Certificate) {
                            certList.add(x509DataObject);
                        }
                    }
                } while(certList.isEmpty());

                this.certChain = (X509Certificate[])((X509Certificate[])certList.toArray(new X509Certificate[0]));
                this.certificate = this.certChain[0];
                return this;
            }
        }

        public Key getKey() {
            return this.certificate.getPublicKey();
        }

        public X509Certificate getCertificate() {
            return this.certificate;
        }

        public X509Certificate[] getCertChain() {
            return this.certChain;
        }
    }
}

