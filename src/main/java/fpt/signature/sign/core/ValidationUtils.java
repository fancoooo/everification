package fpt.signature.sign.core;

import fpt.signature.sign.ex.InvalidCerException;
import fpt.signature.sign.object.ValidateStatus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Date;


public class ValidationUtils {
    public static X509CRL fetchCRLFromURL(URL url) throws Exception {
        CertificateFactory certFactory = null;

        try {
            certFactory = CertificateFactory.getInstance("X509");
        } catch (CertificateException var3) {
            throw new Exception("Error creating BC CertificateFactory provider", var3);
        }

        return fetchCRLFromURLwithRetry(url, certFactory, 3, 100L);
    }

    public static ValidateStatus checkValidTime(X509Certificate cert, Date dateTime) throws InvalidCerException {
        ValidateStatus status = ValidateStatus.UNKNOW;
        if (cert == null) {
            throw new InvalidCerException("Khong doc duoc thong tin chung thu");
        } else {
            if (dateTime == null) {
                dateTime = new Date();
            }

            if (dateTime.before(cert.getNotBefore())) {
                status = ValidateStatus.NOT_YET_VALID;
            } else if (dateTime.after(cert.getNotAfter())) {
                status = ValidateStatus.EXPIRED;
            } else {
                status = ValidateStatus.GOOD;
            }

            return status;
        }
    }

    private static X509CRL fetchCRLFromURLwithRetry(URL url, CertificateFactory certFactory, int retries, long waitTime) throws Exception {
        X509CRL result = null;
        Exception lastException = null;

        for(int i = 0; i < retries && result == null; ++i) {
            try {

                result = fetchCRLFromURL(url, certFactory);
            } catch (Exception var11) {
                lastException = var11;

                try {
                    Thread.sleep(waitTime);
                } catch (InterruptedException var10) {
                    break;
                }
            }
        }

        if (result == null && lastException != null) {
            throw lastException;
        } else {
            return result;
        }
    }

    public static X509CRL fetchCRLFromURL(URL url, CertificateFactory certFactory) throws Exception {
        URLConnection connection;
        try {
            connection = url.openConnection();
        } catch (IOException var22) {
            throw new Exception("Error opening connection for fetching CRL from address : " + url.toString(), var22);
        }

        connection.setDoInput(true);
        byte[] responsearr = null;
        InputStream reader = null;

        try {
            reader = connection.getInputStream();

            int responselen = connection.getContentLength();
            int bread;
            if (responselen != -1) {
                responsearr = new byte[responselen];
                int offset = 0;

                try {
                    while(responselen > 0 && (bread = reader.read(responsearr, offset, responselen)) != -1) {
                        offset += bread;
                        responselen -= bread;
                    }
                } catch (IOException var23) {
                    throw new Exception("Error reading CRL bytes from address : " + url.toString(), var23);
                }

                if (responselen > 0) {
                    throw new Exception("Unexpected EOF encountered while reading crl from : " + url.toString());
                }
            } else {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                while((bread = reader.read()) != -1) {
                    baos.write(bread);
                }

                responsearr = baos.toByteArray();
            }
        } finally {
            if (reader != null) {
                reader.close();
            }

        }

        ByteArrayInputStream bis = new ByteArrayInputStream(responsearr);

        try {
            X509CRL crl = (X509CRL)certFactory.generateCRL(bis);
            return crl;
        } catch (CRLException var20) {
            throw new Exception("Error creating CRL object with bytes from address : " + url.toString(), var20);
        }
    }
}