package fpt.signature.sign.everification.revocation;


import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

import fpt.signature.sign.utils.URLRedirection;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

public class OcspInvocation {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.revocation.OcspInvocation.class);

    private static final int OCSP_CONNECT_TIMEOUT = 5000;

    private static final int OCSP_READ_TIMEOUT = 5000;

    static {
        URLRedirection.disableSslVerification();
    }

    public ValidationResp call(ValidationReq validationReq) {
        ValidationResp validationResp = new ValidationResp();
        int ocspRetry = validationReq.getRetry();
        List<String> ocspUris = validationReq.getOcspUris();
        if (Utils.isNullOrEmpty(ocspUris.get(0))) {
            LOG.debug("No OCSP URL found. This certificate could be SubCA");
            validationResp.setResponseCode(5001);
            return validationResp;
        }
        byte[] ocspData = validationReq.getOcspRequestData();
        for (String uri : ocspUris) {
            while (ocspRetry > 0) {
                try {
                    byte[] ocspResp = postUrl(uri, ocspData);
                    validationResp.setOcspResponseData(ocspResp);
                    validationResp.setResponseCode(0);
                    return validationResp;
                } catch (Exception e) {
                    LOG.error("Ocsp Connection failure. Then retry " + --ocspRetry + ". Details: " + Utils.printStackTrace(e));
                }
            }
            ocspRetry = validationReq.getRetry();
        }
        validationResp.setResponseCode(5001);
        return validationResp;
    }

    public static byte[] postUrl(String ocspUrl, byte[] data) throws Exception {
        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.setConnectTimeout(OCSP_CONNECT_TIMEOUT);
        con.setReadTimeout(OCSP_READ_TIMEOUT);
        con.setDoOutput(true);
        OutputStream out = con.getOutputStream();
        DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
        dataOut.write(data);
        dataOut.flush();
        dataOut.close();
        boolean redirect = false;
        int status = con.getResponseCode();
        if (status != 200 && (
                status == 302 || status == 301 || status == 303))
            redirect = true;
        if (redirect) {
            String newUrl = con.getHeaderField("Location");
            return postUrl(newUrl, data);
        }
        if (status != 200)
            throw new RuntimeException("Unexpected HTTP code while calling OCSP (" + ocspUrl + "): " + status);
        InputStream in = (InputStream)con.getContent();
        return IOUtils.toByteArray(in);
    }
}

