package fpt.signature.sign.everification.objects;


import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.io.source.RandomAccessSourceFactory;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfReverseEx;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.ReaderProperties;
import com.itextpdf.kernel.pdf.StorePages;
import com.itextpdf.signatures.PdfPKCS7;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;

public class PdfSignatureManager implements Runnable {
    private static final Logger LOG = Logger.getLogger(PdfSignatureManager.class);

    private final StoreSignature storage = new StoreSignature();

    private final byte[] signedDoc;

    private final String password;

    private final StorePages storePages = new StorePages();

    public Map<String, StorePages.PositionForm> map_name_pos = new HashMap<>();

    private final int LOOP = 100;

    public PdfSignatureManager(byte[] signedDoc, String password) {
        this.signedDoc = signedDoc;
        this.password = password;
    }

    private void internalProcess() {
        long startTime = System.nanoTime();
        byte[] temporary_byte = this.signedDoc;
        storeSignature(0, temporary_byte, this.password);
        int count = 100;
        while (count > 0) {
            try {
                PdfReader reader = null;
                if (Utils.isNullOrEmpty(this.password)) {
                    reader = new PdfReader((new RandomAccessSourceFactory()).setForceRead(false).createSource(temporary_byte), new ReaderProperties(), true);
                } else {
                    reader = new PdfReader((new RandomAccessSourceFactory()).setForceRead(false).createSource(temporary_byte), (new ReaderProperties()).setPassword(this.password.getBytes()), true);
                }
                byte[] previous = PdfReverseEx.getPreviousVersionFilePdf(reader);
                reader.close();
                if (previous == null) {
                    LOG.debug("Cannot continue to getPrevious File!!");
                    break;
                }
                storeSignature(1, previous, this.password);
                temporary_byte = previous;
                count--;
            } catch (Exception e) {
                long l1 = System.nanoTime();
                long l2 = l1 - startTime;
                LOG.debug("Finished detecting deleted signatures in milliseconds: " + (l2 / 1000000L));
                return;
            }
        }
        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        LOG.debug("Finished detecting deleted signatures in milliseconds: " + (timeElapsed / 1000000L));
    }

    private void storeSignature(int position, byte[] pdf, String password) {
        PdfReader reader = null;
        PdfDocument doc = null;
        try {
            if (Utils.isNullOrEmpty(password)) {
                reader = new PdfReader((new RandomAccessSourceFactory()).setForceRead(false).createSource(pdf), new ReaderProperties(), true);
            } else {
                reader = new PdfReader((new RandomAccessSourceFactory()).setForceRead(false).createSource(pdf), (new ReaderProperties()).setPassword(password.getBytes()), true);
            }
            doc = new PdfDocument(reader);
            if (position == 0)
                this.storePages.storePages(doc);
            PdfDictionary acroFormDictionary = ((PdfDictionary)doc.getCatalog().getPdfObject()).getAsDictionary(PdfName.AcroForm);
            if (acroFormDictionary == null)
                return;
            PdfAcroForm acroForm = PdfAcroForm.getAcroForm(doc, true);
            List<Object[]> sorter = new ArrayList();
            for (Map.Entry<String, PdfFormField> entry : (Iterable<Map.Entry<String, PdfFormField>>)acroForm.getFormFields().entrySet()) {
                PdfFormField field = entry.getValue();
                PdfDictionary merged = (PdfDictionary)field.getPdfObject();
                PdfArray Rect = merged.getAsArray(PdfName.Rect);
                String[] rec = new String[4];
                for (int i = 0; i < Rect.size(); i++)
                    rec[i] = Rect.get(i).toString();
                StorePages.PositionForm form = new StorePages.PositionForm();
                form = this.storePages.getPages(entry.getKey());
                form.setRect(rec);
                this.storePages.getMap_name_positionform().replace(entry.getKey(), form);
                PdfDictionary v = merged.getAsDictionary(PdfName.V);
                if (v != null) {
                    Map<String, String> entryV = null;
                    if (!IsValidSignature(v))
                        entryV = createMapVField(v);
                    PdfString content = (PdfString)v.get(PdfName.Contents);
                    String version = String.valueOf(content.hashCode());
                    byte[] content_byte = content.getValueBytes();
                    String nameForm = entry.getKey();
                    if (this.storage.addSignature(nameForm, version, content_byte, rec, entryV) && position == 0)
                        this.storage.enableVisibleVersion(nameForm, String.valueOf(content.hashCode()));
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    private boolean IsValidSignature(PdfDictionary v) {
        PdfArray byteRange = v.getAsArray(PdfName.ByteRange);
        PdfString contents = v.getAsString(PdfName.Contents);
        if (byteRange != null || contents != null)
            try {
                byte[] byteContent = contents.getValueBytes();
                PdfPKCS7 pkcs7 = new PdfPKCS7(byteContent, PdfName.PatternType, "BC");
                return true;
            } catch (Exception e) {
                return false;
            }
        return false;
    }

    private Map<String, String> createMapVField(PdfDictionary v) {
        Map<String, String> map = new HashMap<>();
        for (PdfName name : v.keySet()) {
            String key = name.getValue();
            PdfObject value = v.get(name);
            if (value.isString()) {
                PdfString value2 = v.getAsString(name);
                map.put(key, value2.toUnicodeString());
                continue;
            }
            map.put(key, value.toString());
        }
        return map;
    }

    public Map<PdfPKCS7, String> getDeletedSignatures() {
        this.storage.getSignatureDeleted_converttoPDFPKCS7();
        return this.storage.getMap_PKCS7_Name();
    }

    public List<StoreSignature.DataSignature> getErrorSignatures() {
        return this.storage.getSignatureError();
    }

    public StoreSignature getStorage() {
        return this.storage;
    }

    public Map<String, StorePages.PositionForm> getMap_name_pos() {
        return this.map_name_pos;
    }

    public void run() {
        internalProcess();
    }

    public StorePages getStorePages() {
        return this.storePages;
    }
}

