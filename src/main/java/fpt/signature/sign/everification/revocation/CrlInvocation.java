package fpt.signature.sign.everification.revocation;


import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import fpt.signature.sign.utils.URLRedirection;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

public class CrlInvocation {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.revocation.CrlInvocation.class);

    private static final int CRL_CONNECT_TIMEOUT = 5000;

    private static final int CRL_READ_TIMEOUT = 5000;

    static {
        URLRedirection.disableSslVerification();
    }

    public ValidationResp call(ValidationReq validationReq) {
        ValidationResp validationResp = new ValidationResp();
        int crlRetry = validationReq.getRetry();
        List<String> crlUirs = validationReq.getCrlUris();
        if (Utils.isNullOrEmpty(crlUirs.get(0))) {

                LOG.debug("No CRL URL found. This certificate could be RootCA");
            validationResp.setResponseCode(5001);
            return validationResp;
        }
        for (String uri : crlUirs) {
            while (crlRetry > 0) {
                try {
                    byte[] crlData = getUrl(uri);
                    validationResp.setResponseCode(0);
                    validationResp.setCrlResponseData(crlData);
                    return validationResp;
                } catch (Exception e) {
                    e.printStackTrace();
                    LOG.error("Crl Connection failure. Then retry " + --crlRetry + ". Details: " + Utils.printStackTrace(e));
                }
            }
            crlRetry = validationReq.getRetry();
        }
        validationResp.setResponseCode(5001);
        return validationResp;
    }

    private byte[] getUrl(String crlUrl) throws Exception {
        URL url = new URL(crlUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);
        con.setDoOutput(true);
        boolean redirect = false;
        int status = con.getResponseCode();
        if (status != 200 && (
                status == 302 || status == 301 || status == 303))
            redirect = true;
        if (redirect) {
            String newUrl = con.getHeaderField("Location");
            return getUrl(newUrl);
        }
        byte[] crlDownloaded = null;
        if (status != 200) {
            crlDownloaded = tryNativeDownload(crlUrl);
            if (crlDownloaded == null)
                throw new RuntimeException("Unexpected HTTP code while calling CRL (" + crlUrl + "): " + status);
        }
        InputStream in = (InputStream)con.getContent();
        crlDownloaded = IOUtils.toByteArray(in);
        if (crlDownloaded == null)
            throw new RuntimeException("Cannot download CRL from " + crlUrl + ". CRL is NULL or EMPTY");
        return crlDownloaded;
    }

    private byte[] tryNativeDownload(String url) {
        byte[] r = null;
        try {
            BufferedInputStream in = new BufferedInputStream((new URL(url)).openStream());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] dataBuffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1)
                baos.write(dataBuffer, 0, bytesRead);
            in.close();
            baos.close();
            r = baos.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Error while download CRL. Details: " + Utils.printStackTrace(e));
        }
        return r;
    }
}

