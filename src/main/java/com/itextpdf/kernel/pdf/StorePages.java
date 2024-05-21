package com.itextpdf.kernel.pdf;

import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class StorePages {
    private Map<String, PositionForm> Map_name_positionform = new HashMap<>();

    public void storePages(PdfDocument document) throws IOException {
        PdfCatalog catalog = document.getCatalog();
        PdfPagesTree pageTree = new PdfPagesTree(document.getCatalog());
        int totalPages = pageTree.getNumberOfPages();
        for (int i = 1; i <= pageTree.getNumberOfPages(); i++) {
            PdfPage pa = pageTree.getPage(i);
            List<PdfAnnotation> anots = pa.getAnnotations();
            for (PdfAnnotation q : anots) {
                PdfDictionary merged = (PdfDictionary)q.getPdfObject();
                PdfString name = merged.getAsString(PdfName.T);
                if (name == null)
                    continue;
                PositionForm test = new PositionForm();
                test.addPage(i);
                if (this.Map_name_positionform.containsKey(name.toString())) {
                    PositionForm pos = this.Map_name_positionform.get(name.toUnicodeString());
                    for (Integer ii : pos.getPageNumber())
                        test.addPage(ii.intValue());
                }
                this.Map_name_positionform.put(name.toUnicodeString(), test);
            }
        }
    }

    public Map<String, PositionForm> getMap_name_positionform() {
        return this.Map_name_positionform;
    }

    public PositionForm getPages(String name) {
        for (String n : this.Map_name_positionform.keySet()) {
            if (n.equalsIgnoreCase(name))
                return this.Map_name_positionform.get(n);
        }
        return null;
    }

    public void listAllPage() {
        for (String a : this.Map_name_positionform.keySet()) {
            System.out.println("Name Sig:" + a);
            PositionForm form = getPages(a);
            System.out.println("Pages:" + form.getPageToString());
            System.out.println("Rect:" + form.getRect_toString());
        }
    }

    public static class PositionForm {
        public List<Integer> pageNumber = new ArrayList<>();

        public String[] rect = new String[4];

        public List<Integer> getPageNumber() {
            return this.pageNumber;
        }

        public String getPageToString() {
            String result = "";
            for (Integer in : this.pageNumber) {
                result = result + in;
                result = result + " ";
            }
            return result;
        }

        public void setPageNumber(List<Integer> pageNumber) {
            this.pageNumber = pageNumber;
        }

        public void addPage(int pageNumber) {
            this.pageNumber.add(Integer.valueOf(pageNumber));
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
    }
}


