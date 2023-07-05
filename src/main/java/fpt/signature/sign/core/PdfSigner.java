package fpt.signature.sign.core;

import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.OcspClientBouncyCastle;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.TSAClient;
import com.lowagie.text.pdf.TSAClientBouncyCastle;
import com.lowagie.text.pdf.PdfPKCS7.X509Name;
import fpt.signature.sign.utils.ResouceFile;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

public class PdfSigner {

    public enum VisibleSigBorder {
        NONE,
        DASHED,
        LINE
    };

    public enum RenderMode {
        TEXT_ONLY,
        TEXT_WITH_BACKGROUND,
        TEXT_WITH_LOGO_LEFT,
        TEXT_WITH_LOGO_TOP,
        LOGO_ONLY
    };

    public enum FontName {
        Times_New_Roman,
        Roboto,
        Arial
    }

    public enum FontStyle {
        Normal,
        Bold,
        Italic,
        BoldItalic,
        Underline
    }

    public static final String REASON = "REASON";
    public static final String REASONDEFAULT = "Signed by SignServer";
    public static final String LOCATION = "LOCATION";
    public static final String LOCATIONDEFAULT = "SignServer";
    public static final String ADD_VISIBLE_SIGNATURE = "ADD_VISIBLE_SIGNATURE";
    public static final boolean ADD_VISIBLE_SIGNATURE_DEFAULT = true;
    public static final String VISIBLE_SIGNATURE_PAGE = "VISIBLE_SIGNATURE_PAGE";
    public static final String VISIBLE_SIGNATURE_PAGE_DEFAULT = "First";
    public static final int VISIBLE_SIGNATURE_PAGE_DEFAULT_INT = 1;
    public static final String VISIBLE_SIGNATURE_RECTANGLE = "VISIBLE_SIGNATURE_RECTANGLE";
    public static final String SIGNATURE_TEXT_SIZE = "SIGNATURE_TEXT_SIZE";
    public static final String TEXTSIZE = "4";
    public static final String SIGNATURE_TEXT_COLORRBG = "SIGNATURE_TEXT_COLORRBG";
    public static final String SIGNATURE_FONT_STYLE = "SIGNATURE_FONT_STYLE";
    public static final String TEXTCOLORRBG = "0,0,255";
    public static final String SIGNATURE_VALIDATIONSTATUS = "SIGNATURE_VALIDATIONSTATUS";
    public static final String VALIDATIONSTATUS = "0";
    public static final String SIGNATURE_TEXTBOLD = "SIGNATURE_TEXTBOLD";
    public static final String TEXTBOLD = "0";
    public static final String SIGNATURE_FONTNAME = "SIGNATURE_FONTNAME";
    public static final String FONTNAME = "font.ttf";
    public static final String SIGNATURE_DESCRIPTION = "SIGNATURE_DESCRIPTION";
    public static final String DESCRIPTION = null;
    public static final String SIGNATURE_DESCRIPTION_ONLY = "SIGNATURE_DESCRIPTION_ONLY";
    public static final String DESCRIPTION_ONLY = "0";
    public static final String SIGNATURE_SIGNER = "SIGNATURE_SIGNER";
    public static final String SIGNATURE_SIGNER_FIXED = null;
    public static final String SIGNATURE_FONT_BOLD_PATH = "SIGNATURE_FONT_BOLD_PATH";
    public static final String SIGNATURE_FONT_BOLD_PATH_DEFAULT = "font.ttf";
    public static final String FONT_ROBOTO = "RobotoCondensed-Light.ttf";
    public static final String SIGNATURE_FONT_PATH = "SIGNATURE_FONT_PATH";
    public static final String SIGNATURE_FONT_PATH_DEFAULT = "font.ttf";
    public static final String SIGNATURE_FONT_MEDIUM_PATH = "SIGNATURE_FONT_MEDIUM_PATH";
    public static final String SIGNATURE_FONT_MEDIUM_PATH_DEFAULT = "font-medium.ttf";
    public static final String SIGNATURE_VISIBLE_TYPE = "SIGNATURE_VISIBLE_TYPE";
    public static final String SIGNATURE_VISIBLE_IN_ALL_PAGES = "SIGNATURE_VISIBLE_IN_ALL_PAGES";
    public static final String MULTIPLE_SINGATURE_VISIBLE = "MULTIPLE_SINGATURE_VISIBLE";
    public static final String VISIBLE_SIGNATURE_RECTANGLE_DEFAULT = "10,10,250,70";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64 = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_RESIZE_TO_RECTANGLE";
    public static final boolean VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE_DEFAULT = true;
    public static final String CERTIFICATION_LEVEL = "CERTIFICATION_LEVEL";
    public static final int CERTIFICATION_LEVEL_DEFAULT = 0;
    public static final String VISIBLE_SIGNATURE_BORDER = "VISIBLE_SIGNATURE_BORDER";
    public static final String VISIBLE_SIGNATURE_BORDER_DEFAULT = "DASHED";
    public static final String VISIBLE_SIGNATURE_SIGNING_TIME_FORMAT = "VISIBLE_SIGNATURE_SIGNING_TIME_FORMAT";
    public static final String VISIBLE_SIGNATURE_TEXT_ISSUER = "VISIBLE_SIGNATURE_TEXT_ISSUER";
    public static final String VISIBLE_SIGNATURE_TEXT_OU = "VISIBLE_SIGNATURE_TEXT_OU";
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    public static final String EMBED_CRL = "EMBED_CRL";
    public static final boolean EMBED_CRL_DEFAULT = false;
    public static final String EMBED_OCSP_RESPONSE = "EMBED_OCSP_RESPONSE";
    public static final boolean EMBED_OCSP_RESPONSE_DEFAULT = false;
    public static final String REFUSE_DOUBLE_INDIRECT_OBJECTS = "REFUSE_DOUBLE_INDIRECT_OBJECTS";
    public static final String REJECT_PERMISSIONS = "REJECT_PERMISSIONS";
    public static final String SET_PERMISSIONS = "SET_PERMISSIONS";
    public static final String REMOVE_PERMISSIONS = "REMOVE_PERMISSIONS";
    public static final String SET_OWNERPASSWORD = "SET_OWNERPASSWORD";
    public static final String PROPERTY_ARCHIVETODISK = "ARCHIVETODISK";
    public static final String PROPERTY_ARCHIVETODISK_PATH_BASE = "ARCHIVETODISK_PATH_BASE";
    public static final String PROPERTY_ARCHIVETODISK_PATH_PATTERN = "ARCHIVETODISK_PATH_PATTERN";
    public static final String PROPERTY_ARCHIVETODISK_FILENAME_PATTERN = "ARCHIVETODISK_FILENAME_PATTERN";
    public static final String DEFAULT_ARCHIVETODISK_PATH_PATTERN = "${DATE:yyyy/MM/dd}";
    public static final String DEFAULT_ARCHIVETODISK_FILENAME_PATTERN = "${WORKERID}-${REQUESTID}-${DATE:HHmmssSSS}.pdf";
    private static final String ARCHIVETODISK_PATTERN_REGEX = "\\$\\{(.+?)\\}";
    private static final String CONTENT_TYPE = "application/pdf";
    public static final String DIGESTALGORITHM = "DIGESTALGORITHM";
    private static final String DEFAULTDIGESTALGORITHM = "SHA1";

    private PdfReader _reader;
    private PdfStamper _stamper;
    private PdfSignatureAppearance _sap;
    private PdfSignature dic;
    private PdfPKCS7 _sgn;

    private Rectangle position;
    private int signingPageInt;
    private TSAClient _tsa;
    private byte[] _ocsp;
    private CRL[] _crl;
    private String _signerName;
    private String _issuerName;
    public String _reason;
    public String _location;
    private String _contact;
    private Rectangle _rectangle;
    public String _page;
    private Calendar _dateTimeCreate;
    private Font _font;
    private float PADDING = 5f;
    private float TILE = 0.6666667f;
    public X509Certificate _signer;
    public X509Certificate[] _certChain;
    private int _signatureEstimatedSize;
    public byte[] _customImage;
    private String _defaultImage;
    public RenderMode _renderMode;
    public VisibleSigBorder _borderType;
    public String _layer2Text;
    private FontName _fontName;
    private int _fontSize;
    private FontStyle _fontStyle;

    public int getFontSize() {
        return _fontSize;
    }

    public void setFontSize(int _fontSize) {
        this._fontSize = _fontSize;
    }
    private int _r;
    private int _g;
    private int _b;
    public Boolean _isVisibleAllPages;
    public Boolean _isVisibleSignature = true;
    public Boolean isUseTimeStamp = false;
    public Boolean isEmbedCrl = false;
    public Boolean isEmbedOcsp = false;

    public String digestAlgorithm = "SHA-256";
    private int minimumPdfVersion;
    private Calendar signingTime;
    public static String _key2FA = null;
    public static boolean _is2FASmartOTP = false;
    public static boolean _is2FAQRCode = false;

    protected static String HASH_ALGORITHM = "SHA1";
    protected static String ENCRYPT_ALGORITHM = "RSA";
    protected byte[] _unsignData;
    protected byte[] _hashOnlyBytes;
    protected byte[] _secondHash;
    protected String _signerCert;
    protected String _tsaUrl;
    protected String _tsaUsername;
    protected String _tsaPassword;

    private ByteArrayOutputStream fout;

    public String SigFieldName;

    public String PdfTemp;

    public String CertSerialNumber;

    public PdfSigner(byte[] unsignData) throws Exception {
        this._signerName = "Me";
        this._issuerName = "CA";
        this._reason = "Document signing";
        this._location = "Location";
        this._contact = "";
        this._rectangle = new Rectangle(25f, 25f, 225f, 75f);
        this._page = "1";
        this._defaultImage = "";
        this._fontSize = 10;
        this.signingTime = Calendar.getInstance();
        try {
            this._unsignData = unsignData;
        } catch (Exception ex) {
        }
    }

    public byte[] Sign(byte[] signeHash) {
        try {
            this._sgn.setExternalDigest(signeHash, null, ENCRYPT_ALGORITHM);
            Calendar cal = Calendar.getInstance();
            byte[] encodedSig = this._sgn.getEncodedPKCS7(this._hashOnlyBytes, this.signingTime, this._tsa, this._ocsp);

            byte[] paddedSig = new byte[this._signatureEstimatedSize];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, (new PdfString(paddedSig)).setHexWriting(true));
            this._sap.close(dic2);
            this._reader.close();
            fout.close();
            return fout.toByteArray();
        } catch (Exception ex) {
            return null;
        }
    }

    private Font calculateFont() {

        Font font = null;

        try {
            //Path path = Paths.get("file/vuArial.ttf");
            String path = ResouceFile.getFontPath();
            System.out.printf("file path font: " + path);

            BaseFont baseFont = BaseFont.createFont(path, "Identity-H", true);
            font = new Font(baseFont, this.getFontSize(), 0, Color.BLACK);
        } catch (Exception var7) {
            System.err.printf(var7.getMessage());
            font  = FontFactory.getFont("Times-Roman", this.getFontSize(), 0, Color.BLACK);
        }
        return font;
    }

    protected TSAClient getTimeStampClient(String url, String username, String password) {
        return new TSAClientBouncyCastle(url, username, password);
    }

    private int calculateEstimatedSignatureSize(Certificate[] certChain, TSAClient tsc, byte[] ocsp, CRL[] crlList) throws Exception {
        int estimatedSize = 0;
        Certificate[] var6 = certChain;
        int var7 = certChain.length;

        int var8;
        for (var8 = 0; var8 < var7; ++var8) {
            Certificate cert = var6[var8];

            try {
                int certSize = cert.getEncoded().length;
                estimatedSize += certSize;
            } catch (CertificateEncodingException var13) {
                throw new Exception("Error estimating signature size contribution for certificate", var13);
            }
        }

        estimatedSize += 2000;
        if (ocsp != null) {
            estimatedSize += ocsp.length;
        }

        if (tsc != null) {
            estimatedSize += 4096;
        }

        if (crlList != null) {
            CRL[] var15 = crlList;
            var7 = crlList.length;

            for (var8 = 0; var8 < var7; ++var8) {
                CRL crl = var15[var8];
                if (crl instanceof X509CRL) {
                    X509CRL x509Crl = (X509CRL) crl;

                    try {
                        int crlSize = x509Crl.getEncoded().length;
                        estimatedSize += crlSize * 2;
                    } catch (CRLException var12) {
                        throw new Exception("Error estimating signature size contribution for CRL", var12);
                    }
                }
            }

            estimatedSize += 100;
        }

        return estimatedSize;
    }

    private void calculateVisibleSignatureBorder(PdfSignatureAppearance sap, VisibleSigBorder borderType) {
        Rectangle rect = sap.getRect();
        PdfTemplate layer2 = sap.getLayer(2);
        switch (borderType) {
            case DASHED:
                layer2.setRGBColorStroke(0, 0, 0);
                layer2.setLineDash(3.0F, 3.0F);
                layer2.rectangle(rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight());
                layer2.stroke();
                break;
            case LINE:
                layer2.setRGBColorStroke(0, 0, 0);
                layer2.setLineDash(1.0F);
                layer2.rectangle(rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight());
                layer2.stroke();
        }

    }

    public static String calculateSigFieldName(PdfReader reader, String fieldName) {
        String newField = fieldName;
        AcroFields fields = reader.getAcroFields();
        if (fields != null) {
            ArrayList<String> sigNames = fields.getSignatureNames();
            if (sigNames != null && !sigNames.isEmpty()) {
                int index = sigNames.size();
                if (sigNames.contains(fieldName)) {
                    newField = fieldName + "-" + index;
                }
            }
        }

        return newField;
    }

    private int getPageNumberForSignature(PdfReader pReader, String pParams) {
        int totalNumOfPages = pReader.getNumberOfPages();
        if (pParams.trim().equals("First")) {
            return 1;
        } else if (pParams.trim().equals("Last")) {
            return totalNumOfPages;
        } else {
            try {
                int pNum = Integer.parseInt(pParams);
                if (pNum < 1) {
                    return 1;
                } else {
                    return pNum > totalNumOfPages ? totalNumOfPages : pNum;
                }
            } catch (NumberFormatException var5) {
                return 1;
            }
        }
    }

    private CRL[] getCrlsForChain(X509Certificate[] certChain) throws Exception {
        List<CRL> retCrls = new ArrayList();

        for (int i = 0; i < certChain.length; i++) {
            Certificate currCert = (Certificate) certChain[i];
            X509CRL currCrl = null;

            try {
                URL currCertURL = getCRLDistributionPoint(currCert);
                if (currCertURL == null) {
                    continue;
                }

                currCrl = ValidationUtils.fetchCRLFromURL(currCertURL);
            } catch (CertificateParsingException var7) {
                throw new Exception("Error obtaining CDP from signing certificate", var7);
            }

            retCrls.add(currCrl);
        }

        return retCrls.isEmpty() ? null : (CRL[]) retCrls.toArray(new CRL[retCrls.size()]);
    }

    static URL getCRLDistributionPoint(Certificate certificate) throws CertificateParsingException {
        return CertTools.getCrlDistributionPoint(certificate);
    }

    private String calculateSigText(Date today, Certificate[] certChain) {
        DateFormat df = new SimpleDateFormat("dd/MM/yyyy");
        String text = "Signature Valid\n";

        X509Name x509Name = PdfPKCS7.getSubjectFields((X509Certificate) certChain[0]);
        if (x509Name != null) {
            text = text + "Ký bởi: " + x509Name.getField("CN");
            String ou = x509Name.getField("OU");
            if (ou != null && !"".equals(ou)) {
            }
        }else{
            text = text + "Signed By: Unknown\n";
            text = text + "Signed Date: " + df.format(today);
        }

        text = text + "\nKý ngày: " + df.format(today);
        //X509Name issuerName = PdfPKCS7.getIssuerFields((X509Certificate) certChain[0]);
//        if (issuerName != null && issuerName.getField("CN") != null) {
//            text = text + "\nAuthentication Organization: " + issuerName.getField("CN");
//        }

        return text;
    }

    public byte[] getSecondHash() throws Exception {
        this.CalculateSignature();
        if (this._secondHash == null) {
            return null;
        }

        return this._secondHash;
    }

    public void CalculateSignature() throws IOException, Exception {
        this._reader = new PdfReader(_unsignData);
        boolean appendMode = true;

        int pdfVersion;
        try {
            pdfVersion = Integer.parseInt(Character.toString(this._reader.getPdfVersion()));
        } catch (NumberFormatException var37) {
            pdfVersion = 0;
        }
        this.fout = new ByteArrayOutputStream();

        char updatedPdfVersion;
        if (this.minimumPdfVersion > pdfVersion) {
            updatedPdfVersion = Character.forDigit(this.minimumPdfVersion, 10);
            AcroFields af = this._reader.getAcroFields();
            List<String> sigNames = af.getSignatureNames();
            if (!sigNames.isEmpty()) {
                throw new Exception("Can not upgrade an already signed PDF and a higher version is required to support the configured digest algorithm");
            }

            appendMode = true;
        } else {
            updatedPdfVersion = 0;
        }

        this._stamper = PdfStamper.createSignature(this._reader, this.fout, '0', (File) null, appendMode);

        this._sap = this._stamper.getSignatureAppearance();

        if (isEmbedCrl) {
            this._crl = this.getCrlsForChain(this._certChain);
        }

        this._sap.setCrypto((PrivateKey) null, this._certChain, this._crl, PdfSignatureAppearance.SELF_SIGNED);
        String url;
        if (this._isVisibleSignature) {
            Date today = this.signingTime.getTime();
            int signaturePage = this.getPageNumberForSignature(this._reader, this._page);


            url = PdfPKCS7.getSubjectFields((X509Certificate) this._certChain[0]).getField("CN");
            String fieldNameFixed = calculateSigFieldName(this._reader, url.replaceAll("[^a-zA-Z0-9 ]+", ""));
            this._sap.setVisibleSignature(this.position, this._reader.getNumberOfPages(), calculateSigFieldName(this._reader, fieldNameFixed));
            this._sap.setAcro6Layers(true);
            String text;
            if (this._layer2Text != null && !"".equals(this._layer2Text)) {
                text = this._layer2Text;
            } else {
                text = this.calculateSigText(today, this._certChain);
            }

            this._sap.setLayer2Text(text);

            switch (this._renderMode) {
                case TEXT_ONLY:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.TEXT_ONLY);
                    break;
                case TEXT_WITH_BACKGROUND:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.TEXT_WITH_BACKGROUND);
                    break;
                case TEXT_WITH_LOGO_LEFT:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.TEXT_WITH_LOGO_LEFT);
                    break;
                case TEXT_WITH_LOGO_TOP:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.TEXT_WITH_LOGO_TOP);
                    break;
                case LOGO_ONLY:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.LOGO_ONLY);
                    break;
                default:
                    this._sap.setRenderMode(PdfSignatureAppearance.RenderMode.NONE);
            }
        }


        byte[] imgData = com.lowagie.text.pdf.codec.Base64.decode("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");

        this.calculateVisibleSignatureBorder(this._sap, this._borderType);
        this._sap.setImage(Image.getInstance(imgData));
        this._sap.setCertificationLevel(0);
        this._sap.setSignDate(this.signingTime);
        //this._sap.setIsVisibleInAllPages(true);
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(this._reason);
        dic.setLocation(this._location);
        dic.setDate(new PdfDate(this.signingTime));
        dic.setName(PdfPKCS7.getSubjectFields((X509Certificate) this._certChain[0]).getField("CN"));
        this._sap.setCryptoDictionary(dic);
        this._font = calculateFont();
        this._sap.setLayer2Font(this._font);

        if (this.isUseTimeStamp) {
            if (this._tsaUrl != null) {
                this._tsa = this.getTimeStampClient(this._tsaUrl, this._tsaUsername, this._tsaPassword);
            }
        }

        if (this.isEmbedOcsp && this._certChain.length >= 2) {
            try {
                url = PdfPKCS7.getOCSPURL((X509Certificate) this._certChain[0]);
                if (url != null && url.length() > 0) {
                    this._ocsp = (new OcspClientBouncyCastle((X509Certificate) this._certChain[0], (X509Certificate) this._certChain[1], url)).getEncoded();
                }
            } catch (CertificateParsingException var36) {
                throw new Exception("Error getting OCSP URL from certificate", var36);
            }
        }

        this._sgn = new PdfPKCS7(null, this._certChain, this._crl, this.digestAlgorithm, (String) null, false);

        this._signatureEstimatedSize = this.calculateEstimatedSignatureSize(this._certChain, this._tsa, this._ocsp, this._crl);

        HashMap<PdfName, Integer> exc = new HashMap();
        exc.put(PdfName.CONTENTS, this._signatureEstimatedSize * 2 + 2);
        this._sap.preClose(exc);
        InputStream data = this._sap.getRangeStream();

        byte[] buf = new byte[8192];

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(this.digestAlgorithm);
        } catch (NoSuchAlgorithmException var32) {
            throw new Exception("Error creating " + this.digestAlgorithm + " digest", var32);
        }

        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }

        this._hashOnlyBytes = messageDigest.digest();
        this._secondHash = this._sgn.getAuthenticatedAttributeBytes(this._hashOnlyBytes, this.signingTime, this._ocsp);
    }

    public void setVisibleSignature(String page, String position) throws Exception {
        if (page == null) {
            throw new Exception("page is null");
        } else if (position == null) {
            throw new Exception("position is null");
        } else {
            try {
                String var3 = page.toUpperCase();
                byte var4 = -1;
                switch(var3.hashCode()) {
                    case 2329238:
                        if (var3.equals("LAST")) {
                            var4 = 1;
                        }
                        break;
                    case 66902672:
                        if (var3.equals("FIRST")) {
                            var4 = 0;
                        }
                }

                switch(var4) {
                    case 0:
                        this.signingPageInt = 1;
                        break;
                    case 1:
                        this.signingPageInt = 0;
                        break;
                    default:
                        this.signingPageInt = Integer.parseInt(page);
                        if (this.signingPageInt < 1) {
                            throw new Exception("Invalid page number");
                        }
                }
            } catch (Exception var6) {
                throw new Exception("Invalid page number " + page, var6);
            }

            int[] iGrid = new int[4];

            try {
                String[] sGrid = position.replace("\n", "").replace("\t", "").replace(" ", "").split(",");

                for(int i = 0; i < 4; ++i) {
                    iGrid[i] = Integer.parseInt(sGrid[i]);
                }

                this.position = new Rectangle((float)iGrid[0], (float)iGrid[1], (float)iGrid[2], (float)iGrid[3]);
            } catch (Exception var7) {
                throw new Exception("Invalid position parameter", var7);
            }
        }
    }
}

