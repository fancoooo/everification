package fpt.signature.sign.everification.core;

import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.io.source.ByteBuffer;
import com.itextpdf.io.util.StreamUtil;
import com.itextpdf.kernel.exceptions.PdfException;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfCatalog;
import com.itextpdf.kernel.pdf.PdfDate;
import com.itextpdf.kernel.pdf.PdfDeveloperExtension;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfIndirectReference;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.PdfVersion;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.PdfSignature;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

import fpt.signature.sign.utils.Crypto;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.util.StreamParsingException;

public class AdobeLtvEnabling {
    private static final Logger LOG = Logger.getLogger(RevocationStatusChecks.class);

    private boolean used = false;

    final PdfDocument pdfDocument;

    final Map<PdfName, ValidationData> validated;

    public void addLtvForChain(X509Certificate certificate, List<X509Certificate> chain, IOcspClient ocspClient, ICrlClient crlClient, PdfName key, boolean forceCrlUsed) throws Exception {
        if (this.used)
            throw new Exception("VERIFICATION_ALREADY_OUTPUT");
        ValidationData validationData = new ValidationData();
        while (certificate != null) {
            X509Certificate issuer = getIssuerCertificate(certificate, chain);

                LOG.debug("Add Certificate " + certificate.getSubjectDN().toString() + " into /Certs");
            validationData.certs.add(certificate.getEncoded());
            byte[] ocspResponse = null;
            if (!forceCrlUsed)
                ocspResponse = ocspClient.getEncoded(certificate, issuer, null);
            if (ocspResponse != null) {

                    LOG.debug("Add OCSP response of certificate " + certificate.getSubjectDN().toString() + " into /OCSPs");
                validationData.ocsps.add(ocspResponse);
                X509Certificate ocspSigner = getOcspSignerCertificate(ocspResponse);
                if (ocspSigner != null) {

                        LOG.debug("\tOCSP response was signed by " + ocspSigner.getSubjectX500Principal().getName());
                    if (!ocspSigner.equals(certificate) &&
                            !Crypto.hasIdPkixOcspNoCheckExtension(ocspSigner) &&
                            !Crypto.isCACertificate(ocspSigner))
                        addLtvForChain(ocspSigner, chain, ocspClient, crlClient, getOcspHashKey(ocspResponse), true);
                }
            } else {
                Collection<byte[]> crl = crlClient.getEncoded(certificate, null);
                if (crl != null && !crl.isEmpty()) {
                        LOG.debug("Add CRL Data of certificate " + certificate.getSubjectDN().toString() + " into /CRLs");
                    validationData.crls.addAll((Collection)crl);
                    for (byte[] crlBytes : crl)
                        addLtvForChain(null, chain, ocspClient, crlClient, getCrlHashKey(crlBytes), false);
                }
            }
            certificate = issuer;
        }
        this.validated.put(key, validationData);
    }

    public void merge() throws IOException {
        if (this.used || this.validated.isEmpty())
            return;
        this.used = true;
        PdfDictionary catalog = (PdfDictionary)this.pdfDocument.getCatalog().getPdfObject();
        PdfObject dss = catalog.get(PdfName.DSS);
        if (dss == null) {
            createDss();
        } else {
            updateDss();
        }
    }

    private void createDss() throws IOException {
        outputDss(new PdfDictionary(), new PdfDictionary(), new PdfArray(), new PdfArray(), new PdfArray());
    }

    private void updateDss() throws IOException {
        PdfDictionary catalog = (PdfDictionary)this.pdfDocument.getCatalog().getPdfObject();
        catalog.setModified();
        PdfDictionary dss = catalog.getAsDictionary(PdfName.DSS);
        PdfArray ocsps = dss.getAsArray(PdfName.OCSPs);
        PdfArray crls = dss.getAsArray(PdfName.CRLs);
        PdfArray certs = dss.getAsArray(PdfName.Certs);
        dss.remove(PdfName.OCSPs);
        dss.remove(PdfName.CRLs);
        dss.remove(PdfName.Certs);
        PdfDictionary vrim = dss.getAsDictionary(PdfName.VRI);
        if (vrim != null)
            for (PdfName n : vrim.keySet()) {
                if (this.validated.containsKey(n)) {
                    PdfDictionary vri = vrim.getAsDictionary(n);
                    if (vri != null) {
                        deleteOldReferences(ocsps, vri.getAsArray(PdfName.OCSP));
                        deleteOldReferences(crls, vri.getAsArray(PdfName.CRL));
                        deleteOldReferences(certs, vri.getAsArray(PdfName.Cert));
                    }
                }
            }
        if (ocsps == null)
            ocsps = new PdfArray();
        if (crls == null)
            crls = new PdfArray();
        if (certs == null)
            certs = new PdfArray();
        if (vrim == null)
            vrim = new PdfDictionary();
        outputDss(dss, vrim, ocsps, crls, certs);
    }

    public void outputDss(PdfDictionary dss, PdfDictionary vrim, PdfArray ocsps, PdfArray crls, PdfArray certs) throws IOException {
        PdfCatalog catalog = this.pdfDocument.getCatalog();
        if (this.pdfDocument.getPdfVersion().compareTo(PdfVersion.PDF_2_0) < 0) {
            catalog.addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
            catalog.addDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));
        }
        for (PdfName vkey : this.validated.keySet()) {
            PdfArray ocsp = new PdfArray();
            PdfArray crl = new PdfArray();
            PdfArray cert = new PdfArray();
            PdfDictionary vri = new PdfDictionary();
            for (byte[] b : ((ValidationData)this.validated.get(vkey)).crls) {
                PdfStream ps = new PdfStream(b);
                ps.setCompressionLevel(-1);
                ps.makeIndirect(this.pdfDocument);
                crl.add((PdfObject)ps);
                crls.add((PdfObject)ps);
                crls.setModified();
            }
            for (byte[] b : ((ValidationData)this.validated.get(vkey)).ocsps) {
                b = buildOCSPResponse(b);
                PdfStream ps = new PdfStream(b);
                ps.setCompressionLevel(-1);
                ps.makeIndirect(this.pdfDocument);
                ocsp.add((PdfObject)ps);
                ocsps.add((PdfObject)ps);
                ocsps.setModified();
            }
            for (byte[] b : ((ValidationData)this.validated.get(vkey)).certs) {
                PdfStream ps = new PdfStream(b);
                ps.setCompressionLevel(-1);
                ps.makeIndirect(this.pdfDocument);
                cert.add((PdfObject)ps);
                certs.add((PdfObject)ps);
                certs.setModified();
            }
            if (ocsp.size() > 0) {
                ocsp.makeIndirect(this.pdfDocument);
                vri.put(PdfName.OCSP, (PdfObject)ocsp);
            }
            if (crl.size() > 0) {
                crl.makeIndirect(this.pdfDocument);
                vri.put(PdfName.CRL, (PdfObject)crl);
            }
            if (cert.size() > 0) {
                cert.makeIndirect(this.pdfDocument);
                vri.put(PdfName.Cert, (PdfObject)cert);
            }
            vri.put(PdfName.TU, (new PdfDate()).getPdfObject());
            vri.makeIndirect(this.pdfDocument);
            vrim.put(vkey, (PdfObject)vri);
        }
        vrim.makeIndirect(this.pdfDocument);
        vrim.setModified();
        dss.put(PdfName.VRI, (PdfObject)vrim);
        if (ocsps.size() > 0) {
            ocsps.makeIndirect(this.pdfDocument);
            dss.put(PdfName.OCSPs, (PdfObject)ocsps);
        }
        if (crls.size() > 0) {
            crls.makeIndirect(this.pdfDocument);
            dss.put(PdfName.CRLs, (PdfObject)crls);
        }
        if (certs.size() > 0) {
            certs.makeIndirect(this.pdfDocument);
            dss.put(PdfName.Certs, (PdfObject)certs);
        }
        dss.makeIndirect(this.pdfDocument);
        dss.setModified();
        catalog.put(PdfName.DSS, (PdfObject)dss);
    }

    static PdfName getCrlHashKey(byte[] crlBytes) throws NoSuchAlgorithmException, IOException, CRLException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlBytes));
        byte[] signatureBytes = crl.getSignature();
        DEROctetString octetString = new DEROctetString(signatureBytes);
        byte[] octetBytes = octetString.getEncoded();
        byte[] octetHash = hashBytesSha1(octetBytes);
        PdfName octetName = new PdfName(convertToHex(octetHash));
        return octetName;
    }

    static PdfName getOcspHashKey(byte[] basicResponseBytes) throws NoSuchAlgorithmException, IOException {
        BasicOCSPResponse basicResponse = BasicOCSPResponse.getInstance(basicResponseBytes);
        byte[] signatureBytes = basicResponse.getSignature().getBytes();
        DEROctetString octetString = new DEROctetString(signatureBytes);
        byte[] octetBytes = octetString.getEncoded();
        byte[] octetHash = hashBytesSha1(octetBytes);
        PdfName octetName = new PdfName(convertToHex(octetHash));
        return octetName;
    }

    public static PdfName getSignatureHashKey(PdfSignature sig) throws NoSuchAlgorithmException, IOException {
        PdfString contents = sig.getContents();
        byte[] bc = PdfEncodings.convertToBytes(contents.getValue(), null);
        byte[] bt = null;
        if (PdfName.ETSI_RFC3161.equals(sig.getSubFilter())) {
            ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(bc));
            ASN1Primitive pkcs = din.readObject();
            bc = pkcs.getEncoded();
        }
        bt = hashBytesSha1(bc);
        return new PdfName(convertToHex(bt));
    }

    static byte[] hashBytesSha1(byte[] b) throws NoSuchAlgorithmException {
        MessageDigest sh = MessageDigest.getInstance("SHA1");
        return sh.digest(b);
    }

    static String convertToHex(byte[] bytes) {
        ByteBuffer buf = new ByteBuffer();
        for (byte b : bytes)
            buf.appendHex(b);
        return PdfEncodings.convertToString(buf.toByteArray(), null).toUpperCase();
    }

    public static X509Certificate getOcspSignerCertificate(byte[] basicResponseBytes) throws CertificateException, OCSPException, OperatorCreationException {
        JcaX509CertificateConverter converter = (new JcaX509CertificateConverter()).setProvider("BC");
        BasicOCSPResponse borRaw = BasicOCSPResponse.getInstance(basicResponseBytes);
        BasicOCSPResp bor = new BasicOCSPResp(borRaw);
        for (X509CertificateHolder x509CertificateHolder : bor.getCerts()) {
            X509Certificate x509Certificate = converter.getCertificate(x509CertificateHolder);
            JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
            jcaContentVerifierProviderBuilder.setProvider("BC");
            PublicKey publicKey = x509Certificate.getPublicKey();
            ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(publicKey);
            if (bor.isSignatureValid(contentVerifierProvider))
                return x509Certificate;
        }
        return null;
    }

    public static X509Certificate getOcspSignerCert(byte[] basicResponseBytes) {
        try {
            return getOcspSignerCertificate(basicResponseBytes);
        } catch (Exception exception) {
            return null;
        }
    }

    private static byte[] buildOCSPResponse(byte[] basicOcspResponse) throws IOException {
        DEROctetString doctet = new DEROctetString(basicOcspResponse);
        OCSPResponseStatus respStatus = new OCSPResponseStatus(0);
        ResponseBytes responseBytes = new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, (ASN1OctetString)doctet);
        OCSPResponse ocspResponse = new OCSPResponse(respStatus, responseBytes);
        return (new OCSPResp(ocspResponse)).getEncoded();
    }

    static X509Certificate getIssuerCertificate(X509Certificate certificate) throws IOException, StreamParsingException {
        String url = getCACURL(certificate);
        if (url != null && url.length() > 0) {
            HttpURLConnection con = (HttpURLConnection)(new URL(url)).openConnection();
            if (con.getResponseCode() / 100 != 2)
                throw (new PdfException("Invalid http response {0}.")).setMessageParams(new Object[] { Integer.valueOf(con.getResponseCode()) });
            InputStream inp = (InputStream)con.getContent();
            X509CertParser parser = new X509CertParser();
            parser.engineInit(new ByteArrayInputStream(StreamUtil.inputStreamToArray(inp)));
            return (X509Certificate)parser.engineRead();
        }
        return null;
    }

    static X509Certificate getIssuerCertificate(Certificate certificate, List<X509Certificate> chain) {
        for (X509Certificate c : chain) {
            try {
                certificate.verify(c.getPublicKey());
                if (certificate.equals(c))
                    return null;
                return c;
            } catch (Exception exception) {}
        }
        return null;
    }

    static String getCACURL(X509Certificate certificate) {
        try {
            ASN1Primitive obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
            if (obj == null)
                return null;
            ASN1Sequence AccessDescriptions = (ASN1Sequence)obj;
            for (int i = 0; i < AccessDescriptions.size(); i++) {
                ASN1Sequence AccessDescription = (ASN1Sequence)AccessDescriptions.getObjectAt(i);
                if (AccessDescription.size() == 2)
                    if (AccessDescription.getObjectAt(0) instanceof ASN1ObjectIdentifier) {
                        ASN1ObjectIdentifier id = (ASN1ObjectIdentifier)AccessDescription.getObjectAt(0);
                        if ("1.3.6.1.5.5.7.48.2".equals(id.getId())) {
                            ASN1Primitive description = (ASN1Primitive)AccessDescription.getObjectAt(1);
                            String AccessLocation = getStringFromGeneralName(description);
                            if (AccessLocation == null)
                                return "";
                            return AccessLocation;
                        }
                    }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null)
            return null;
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString)aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }

    private static String getStringFromGeneralName(ASN1Primitive names) throws IOException {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject)names;
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets(), "ISO-8859-1");
    }

    public AdobeLtvEnabling(PdfDocument pdfDocument) {
        this.validated = new HashMap<>();
        this.pdfDocument = pdfDocument;
    }

    private static void deleteOldReferences(PdfArray all, PdfArray toDelete) {
        if (all == null || toDelete == null)
            return;
        for (PdfObject pi : toDelete) {
            PdfIndirectReference pir = pi.getIndirectReference();
            for (int i = 0; i < all.size(); i++) {
                PdfIndirectReference pod = all.get(i).getIndirectReference();
                if (Objects.equals(pir, pod)) {
                    all.remove(i);
                    i--;
                }
            }
        }
    }

    class ValidationData {
        final List<byte[]> crls = new ArrayList();
        final List<byte[]> ocsps = new ArrayList();
        final List<byte[]> certs = new ArrayList();
    }
}

