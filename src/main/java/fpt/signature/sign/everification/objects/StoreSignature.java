package fpt.signature.sign.everification.objects;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.signatures.PdfPKCS7;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class StoreSignature {
    public List<String> form;

    public Map<String, Signature> storage;

    public Map<PdfPKCS7, String> map_PKCS7_Name;

    public Map<DataSignature, String> map_Name_v;

    static {
        Security.addProvider((Provider)new BouncyCastleProvider());
    }

    public StoreSignature() {
        if (this.form == null)
            this.form = new ArrayList<>();
        if (this.storage == null)
            this.storage = new HashMap<>();
        if (this.map_PKCS7_Name == null)
            this.map_PKCS7_Name = new HashMap<>();
    }

    public boolean enableVisibleVersion(String nameSignature, String inputVersion) {
        if (nameSignature == null || inputVersion == null)
            return false;
        Signature signature = this.storage.get(nameSignature);
        for (String version : signature.VersionData.keySet()) {
            DataSignature temp = signature.VersionData.get(version);
            if (version.equals(inputVersion)) {
                temp.isdeleted = false;
                continue;
            }
            temp.isdeleted = true;
        }
        return true;
    }

    public boolean addSignature(String nameForm, String nameVersionSig, byte[] signatureValues, String[] rec, Map<String, String> v) {
        if (nameForm == null)
            return false;
        if (this.form.contains(nameForm))
            return addSignature_add(nameForm, nameVersionSig, signatureValues, rec, v);
        return addSignature_createnew(nameForm, nameVersionSig, signatureValues, rec, v);
    }

    private boolean addSignature_createnew(String nameForm, String nameVersionSig, byte[] signatureValues, String[] rec, Map<String, String> v) {
        try {
            Signature temp = new Signature();
            temp.setList_rect(rec);
            temp.addVersion(nameVersionSig, signatureValues, v);
            this.form.add(nameForm);
            this.storage.put(nameForm, temp);
            return true;
        } catch (Exception ex) {
            Logger.getLogger(StoreSignature.class.getName()).log(Level.SEVERE, (String)null, ex);
            return false;
        }
    }

    private boolean addSignature_add(String name, String version, byte[] signatureValues, String[] rec, Map<String, String> v) {
        try {
            Signature sig = this.storage.get(name);
            sig.setList_rect(rec);
            sig.addVersion(version, signatureValues, v);
            this.storage.put(name, sig);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public List<PdfPKCS7> getSignatureDeleted_converttoPDFPKCS7() {
        List<PdfPKCS7> result = new ArrayList<>();
        this.map_PKCS7_Name.clear();
        for (String name : this.form) {
            Signature sig = this.storage.get(name);
            for (String key : sig.VersionData.keySet()) {
                DataSignature revison = sig.VersionData.get(key);
                if (!revison.isDeleted())
                    continue;
                if (revison.isError())
                    continue;
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider((Provider)provider);
                PdfPKCS7 pkcs = new PdfPKCS7(((DataSignature)sig.VersionData.get(key)).getContents(), PdfName.PatternType, provider.getName());
                result.add(pkcs);
                this.map_PKCS7_Name.put(pkcs, name);
            }
        }
        return result;
    }

    public Map<PdfPKCS7, String> getMap_PKCS7_Name() {
        return this.map_PKCS7_Name;
    }

    public List<PdfPKCS7> getSignatureNotDeleted_converttoPDFPKCS7() {
        List<PdfPKCS7> result = new ArrayList<>();
        this.map_PKCS7_Name.clear();
        for (String name : this.form) {
            Signature sig = this.storage.get(name);
            for (String key : sig.VersionData.keySet()) {
                DataSignature revison = sig.VersionData.get(key);
                if (revison.isDeleted() || revison.isError())
                    continue;
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider((Provider)provider);
                PdfPKCS7 pkcs = new PdfPKCS7(((DataSignature)sig.VersionData.get(key)).getContents(), PdfName.PatternType, provider.getName());
                result.add(pkcs);
                this.map_PKCS7_Name.put(pkcs, name);
            }
        }
        return result;
    }

    public List<DataSignature> getSignatureError() {
        if (this.map_Name_v == null)
            this.map_Name_v = new HashMap<>();
        List<DataSignature> result = new ArrayList<>();
        for (String name : this.form) {
            Signature sig = this.storage.get(name);
            for (String key : sig.VersionData.keySet()) {
                DataSignature revison = sig.VersionData.get(key);
                if (!revison.isError())
                    continue;
                result.add(revison);
                this.map_Name_v.put(revison, name);
            }
        }
        return result;
    }

    public class Signature {
        public List<String> nameVersion;

        public Map<String, StoreSignature.DataSignature> VersionData;

        private String[] list_rect;

        public Signature() {
            if (this.nameVersion == null)
                this.nameVersion = new ArrayList<>();
            if (this.VersionData == null)
                this.VersionData = new HashMap<>();
            if (this.list_rect == null)
                this.list_rect = new String[4];
        }

        public List<String> getName() {
            return this.nameVersion;
        }

        public void setName(List<String> nameVersion) {
            this.nameVersion = nameVersion;
        }

        public String[] getList_rect() {
            return this.list_rect;
        }

        public void setList_rect(String[] list_rect) {
            this.list_rect = list_rect;
        }

        public int getTotalVersion() {
            return this.nameVersion.size();
        }

        public void addVersion(String inputVersion, byte[] v_field, Map<String, String> v) throws Exception {
            addVersion(inputVersion, v_field, true, v);
        }

        public void addVersion(String inputVersion, byte[] v_field, boolean isDel, Map<String, String> v) throws Exception {
            if (this.nameVersion.contains(inputVersion))
                throw new Exception("This version is already stored");
            if (this.list_rect.length == 0 || this.list_rect == null)
                throw new Exception("Input Rectangle");
            this.nameVersion.add(inputVersion);
            StoreSignature.DataSignature temp = new StoreSignature.DataSignature();
            temp.setIsdeleted(isDel);
            temp.setContents(v_field);
            temp.setRect(this.list_rect);
            temp.setvField(v);
            temp.setError(!(v == null));
            this.list_rect = null;
            this.VersionData.put(inputVersion, temp);
        }
    }

    public class DataSignature {
        private byte[] Contents;

        private boolean isdeleted;

        private String[] rect;

        private boolean isError;

        private Map<String, String> vField;

        public byte[] getContents() {
            return this.Contents;
        }

        public void setContents(byte[] Contents) {
            this.Contents = Contents;
        }

        public boolean isDeleted() {
            return this.isdeleted;
        }

        public void setIsdeleted(boolean isdeleted) {
            this.isdeleted = isdeleted;
        }

        public String[] getRect() {
            return this.rect;
        }

        public void setRect(String[] rect) {
            this.rect = rect;
        }

        public String getRect_toString() {
            return this.rect[0] + " " + this.rect[1] + " " + this.rect[2] + " " + this.rect[3];
        }

        public boolean isError() {
            return this.isError;
        }

        public void setError(boolean isError) {
            this.isError = isError;
        }

        public Map<String, String> getvField() {
            return this.vField;
        }

        public void setvField(Map<String, String> vField) {
            this.vField = vField;
        }
    }
}

