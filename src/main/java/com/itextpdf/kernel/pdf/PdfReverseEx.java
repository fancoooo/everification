package com.itextpdf.kernel.pdf;

import com.itextpdf.io.source.PdfTokenizer;
import com.itextpdf.io.source.RandomAccessFileOrArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfReverse;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PdfReverseEx {
    public static String getPrev_UsingTokenizer(String input) {
        StringTokenizer token = new StringTokenizer(input, "/", false);
        while (token.hasMoreTokens()) {
            String q;
            if ((q = token.nextToken()).matches("Prev .+?"))
                return q.replaceAll("Prev ", "");
        }
        return null;
    }

    public static String getPrev(PdfDocument doc) {
        try {
            PdfDictionary trailers = doc.getTrailer();
            PdfObject result = trailers.get(PdfName.Prev);
            return result.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static int moveToEOF(PdfReader reader) throws IOException {
        int ch;
        do {
            ch = reader.tokens.read();
            if (ch == 49 && reader.tokens.read() == 49 && reader.tokens.read() == 54 && reader.tokens
                    .read() == 13 && reader.tokens.read() == 10)
                return -1;
        } while (ch != 69 || reader.tokens.read() != 79 || reader.tokens.read() != 70);
        return (int)reader.tokens.getPosition();
    }

    public static byte[] getPreviousVersionFilePdf(PdfReader reader) {
        try {
            PdfDocument pdfDoc = new PdfDocument(reader);
            String temp = getPrev(pdfDoc);
            if (temp == null)
                return null;
            int prev = Integer.parseInt(temp);
            if (prev == 116)
                prev += 1024;
            reader.tokens.seek(prev);
            int movetoEOF = moveToEOF(reader);
            if (movetoEOF == 1)
                return null;
            reader.tokens.seek(0L);
            return readArrayByte(movetoEOF, reader);
        } catch (NegativeArraySizeException ex) {
            return null;
        } catch (IOException ex) {
            Logger.getLogger(PdfReverse.class.getName()).log(Level.SEVERE, (String)null, ex);
            return null;
        }
    }

    public static byte[] readArrayByte(int size, PdfReader reader) throws IOException {
        PdfTokenizer token = reader.tokens;
        RandomAccessFileOrArray aray = reader.getSafeFile();
        byte[] filePDF = new byte[size];
        int position = 0;
        while (size-- > 0) {
            byte temp = aray.readByte();
            filePDF[position] = temp;
            position++;
        }
        return filePDF;
    }

    public static void writeToFile(byte[] input, String dest) {
        try {
            FileOutputStream out = new FileOutputStream(new File(dest));
            out.write(input);
            out.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PdfReverse.class.getName()).log(Level.SEVERE, (String)null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PdfReverse.class.getName()).log(Level.SEVERE, (String)null, ex);
        }
    }
}

