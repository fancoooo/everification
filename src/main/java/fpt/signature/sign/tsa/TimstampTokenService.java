package fpt.signature.sign.tsa;

import ch.qos.logback.core.net.SyslogOutputStream;
import fpt.signature.sign.utils.HashUtils;
import fpt.signature.sign.utils.Settings;
import fpt.signature.sign.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.ietf.jgss.Oid;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class TimstampTokenService {
    public TsaResponse getToken(TsaRequest req, HttpServletRequest request) throws UnsupportedEncodingException {

        TsaResponse response = new TsaResponse();

        Date time = Calendar.getInstance().getTime();
        String uuid = UUID.randomUUID().toString().replace("-","");

        response.content.transactionId = req.content.transactionId;
        response.info.version = req.info.version;
        response.info.senderId = req.info.receiverId;
        response.info.receiverId = req.info.senderId;
        response.info.messageType = 202;

        response.info.sendDate = (long)time.getTime();
        response.info.messageId = response.info.senderId + new SimpleDateFormat("yyMM").format(time) + uuid.toUpperCase();
        response.info.referenceMessageId = req.info.messageId;

        String XKey = Utils.getRequestHeader(request,"X-API-KEY");
        if(XKey == null && XKey.trim().isEmpty()){
            response.info.responseCode = 207;
            response.info.responseMessage = "Lỗi này xảy ra khi Trục gửi thiếu thông tin API-Key";
            return response;
        }


        // Verify X-API-Key
        if (!XKey.equals(Settings.API_KEY_PRO) && !XKey.equals(Settings.API_KEY_UAT) && !XKey.equals(Settings.API_KEY_UAT_1))
        {
            response.info.responseCode = 207;
            response.info.responseMessage = "Lỗi này xảy ra khi Trục gửi sai thông tin API-Key";
            return response;
        }
        String json = Utils.toJSONString(req.content);
        String a = Utils.printHexBinary(HashUtils.hashData(Utils.toJSONString(req.info).getBytes(StandardCharsets.US_ASCII), "SHA256"))+ "." + Utils.printHexBinary(HashUtils.hashData(Utils.toJSONString(req.content).getBytes(StandardCharsets.US_ASCII), "SHA256"));
        String signatue = Utils.printHexBinary(Utils.calcHmacSha256(Settings.SECRET_KEY_PRO.getBytes(StandardCharsets.US_ASCII), a.getBytes(StandardCharsets.US_ASCII)));

        String signatue1 = Utils.printHexBinary(Utils.calcHmacSha256(Settings.SECRET_KEY_UAT.getBytes(StandardCharsets.US_ASCII), a.getBytes(StandardCharsets.US_ASCII)));

        String signatue2 = Utils.printHexBinary(Utils.calcHmacSha256(Settings.SECRET_KEY_UAT_1.getBytes(StandardCharsets.US_ASCII), a.getBytes(StandardCharsets.US_ASCII)));

        if (!signatue.toUpperCase().equals(req.signature.toUpperCase()) && !signatue1.toUpperCase().equals(req.signature.toUpperCase()) && !signatue2.toUpperCase().equals(req.signature.toUpperCase()))
        {
            response.info.responseCode = 208;
            response.info.responseMessage = "Lỗi này xảy ra khi Trục gửi sai thông tin signature";
            return response;
        }

        byte[] data;
        try
        {
            data = Utils.parseHexBinary(req.content.data.digest);
        }
        catch (Exception ex)
        {
            response.info.responseCode = 201;
            response.info.responseMessage = "Lỗi dữ liệu từ CeCA gửi sang";
            return response;
        }

        int statusCode;
        String statusMessage;
        byte[] tsaResponse;

        try
        {
            TimeStampResponse tsa = GetTimestampResponse(data, true);

            byte[] timestamp = tsa.getTimeStampToken().getEncoded();

            TimeStampToken token = new TimeStampToken(new CMSSignedData(timestamp));


            Date tsaTime = token.getTimeStampInfo().getGenTime();

            SimpleDateFormat  tx = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
            tx.setTimeZone(TimeZone.getTimeZone("UTC"));
            response.content.data = new DataR(Utils.printHexBinary(timestamp), tx.format(tsaTime),"SHA256withRSA" );

            response.info.responseCode = 0;
            response.info.responseMessage = "Provider trả thông điệp thành công";

        }
        catch (Exception ex)
        {
            response.info.responseCode = 203;
            response.info.responseMessage = "Dữ liệu phản hồi từ Provider không hợp lệ : " + ex.getMessage() + " : "  + ex.getMessage();
            return response;
        }
        finally
        {
            Date time1 = Calendar.getInstance().getTime();
            String uuid1 = UUID.randomUUID().toString().replace("-","");
            response.content.transactionId = req.content.transactionId;
            response.info.version = req.info.version;
            response.info.senderId = req.info.receiverId;
            response.info.receiverId = req.info.senderId;
            response.info.messageType = 202;
            response.info.sendDate = (long)time1.getTime();;
            response.info.messageId = response.info.senderId + new SimpleDateFormat("yyMM").format(time) + uuid.toUpperCase();
            response.info.referenceMessageId = req.info.messageId;
        }

        return response;
    }

    private TimeStampResponse GetTimestampResponse(byte[] imprint, Boolean IncludeNonce) throws Exception {
        String str;
        TimeStampRequestGenerator generator;
        TimeStampRequest request;
        BigInteger integer;
        byte[] buffer;
        TimeStampResponse response;
        byte[] buffer2;
        try
        {
            str = "2.16.840.1.101.3.4.2.1"; // SHA256
            generator = new TimeStampRequestGenerator();
            generator.setCertReq(true);
            generator.setReqPolicy("1.3.6.1.4.1.13762.3");
            request = null;
            if (!IncludeNonce)
            {
                request = generator.generate(str, imprint);
            }
            else
            {
                integer = BigInteger.valueOf(new Date().getTime());
                request = generator.generate(str, imprint, integer);
            }
            buffer = GetTSAResponse(request.getEncoded());
            response = new TimeStampResponse(buffer);
            response.validate(request);
        }
        catch (Exception exception)
        {
            throw new Exception("Error on obtaining the TSA Response. Error: " + exception.getMessage());
        }
        return response;
    }

    private byte[] GetTSAResponse(byte[] requestBytes) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(Settings.TSA_URL).openConnection();
        connection.setRequestMethod("POST");

        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        String auth = new String(Base64.getEncoder().encode((Settings.TSA_USERNAME + ":" + Settings.TSA_PASSWORD).getBytes("ASCII")));
        connection.setRequestProperty("Authorization", "Basic " + auth);
        connection.setRequestProperty("User-Agent", "TSAEngine");


        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);

        try {
            if (requestBytes != null) {
                DataOutputStream wr = new DataOutputStream(
                        connection.getOutputStream());
                wr.write(requestBytes);
                wr.flush();
                wr.close();

                InputStream is;
                try {
                    is = connection.getInputStream();
                    return IOUtils.toByteArray(is);
                } catch (IOException e) {
                    throw e;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Request failed. " + e.getMessage(), e);
        }
        return null;
    }

}
