package fpt.signature.sign.aws;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

import fpt.signature.sign.aws.datatypes.PadesConstants;
import fpt.signature.sign.aws.datatypes.PrintResponse;
import fpt.signature.sign.aws.request.PadesRequset;
import fpt.signature.sign.aws.response.PadesResponse;
import fpt.signature.sign.aws.response.TokenResponse;
import vn.mobileid.aws.client.AWSV4Auth;
import vn.mobileid.aws.client.AWSV4Constants;

/**
 * 2021/10/06
 *
 * @author TuoiCm
 */
public class AWSCall {

    final protected static String FILE_DIRECTORY_PDF = "file/";
    private URL url;
    private String httpMethod;
    private String accessKey;
    private String secretKey;
    private String regionName;
    private String serviceName;
    private int timeOut;
    private String xApiKey;
    private String contentType;
    public String sessionToken;
    public String bearerToken;
    private TreeMap<String, String> awsHeaders;
    private AWSV4Auth.Builder builder;

    public AWSCall(String httpMethod, String accessKey,
                   String secretKey, String regionName,
                   String serviceName, int timeOut,
                   String xApiKey, String contentType) throws MalformedURLException {
        this.httpMethod = httpMethod;
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.regionName = regionName;
        this.serviceName = serviceName;
        this.timeOut = timeOut;
        this.xApiKey = xApiKey;
        this.contentType = contentType;
        this.url = new URL(PadesConstants.BASE_URL);

        this.awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSV4Constants.X_API_KEY, this.xApiKey);
        awsHeaders.put(AWSV4Constants.CONTENT_TYPE, this.contentType);

        this.builder = new AWSV4Auth.Builder(accessKey, secretKey)
                .regionName(regionName)
                .serviceName(serviceName)
                .httpMethodName(httpMethod)// GET, PUT, POST, DELETE
                .queryParametes(null) // query parameters if any
                .awsHeaders(awsHeaders); // aws header parameters
    }

    //AWS4Auth
    public Map<String, String> getAWSV4Auth(String payload, String function, String token) throws MalformedURLException {
        this.awsHeaders.put(PadesConstants.SESSION_TOKEN, token);
        AWSV4Auth aWSV4Auth = this.builder
                .endpointURI(new URL(this.url.toString())) //https://id.mobile-id.vn/dtis/v1/e-verification/oidc/token
                .payload(payload)
                .build();
        return aWSV4Auth.getHeaders();
    }

    // v1/e-verification/oidc/token
    public void v1VeriOidcToken(String function, String token) throws MalformedURLException, IOException {
        //System.out.println(this.bearerToken);
        //Send Post
        String jsonResp = HttpUtils.invokeHttpRequest(
                this.url = new URL(PadesConstants.BASE_URL + function),
                this.httpMethod,
                this.timeOut,
                getAWSV4Auth(null, function, token),
                null);
        //Response
        ObjectMapper objectMapper = new ObjectMapper();
        TokenResponse tokenResponse = objectMapper.readValue(jsonResp, TokenResponse.class);
        //Past Bearer for Step 2 (E-verification/pades)
        this.bearerToken = "Bearer " + tokenResponse.access_token;
        PrintResponse.printRespOdicToken(tokenResponse);
    }

    // v1/e-verification/pades
    public void v1VerificationPades(
            String function,
            String lang,
            boolean signerInformation,
            boolean certificatesInformation,
            String fileNamePDF,
            String token) throws IOException {

        String base64PDF = PDFToBase64(FILE_DIRECTORY_PDF, fileNamePDF);

        //Request
        PadesRequset padesRequset = new PadesRequset();
        padesRequset.setLang(lang);
        padesRequset.setSigner_information(signerInformation);
        padesRequset.setCertificates_information(certificatesInformation);
        padesRequset.setDocument(base64PDF);

        //Convert Request To Json
        ObjectMapper objectMapper = new ObjectMapper();
        String payload = objectMapper.writeValueAsString(padesRequset);
        //Send Post
        String jsonPadesResp = HttpUtils.invokeHttpRequest(
                this.url = new URL(PadesConstants.BASE_URL + function),
                httpMethod,
                timeOut,
                getAWSV4Auth(payload, function, token),
                payload);
        //Response
        PadesResponse padesResponse = objectMapper.readValue(jsonPadesResp, PadesResponse.class);
        PrintResponse.printRespPades(padesResponse);
    }

    //Convert PDF File To Base64
    public String PDFToBase64(String fileDirectoryPDF, String PDFFileName) throws IOException {
        byte[] input_file = Files.readAllBytes(Paths.get(fileDirectoryPDF + PDFFileName));
        Base64.Encoder enc = Base64.getEncoder();
        byte[] strenc = enc.encode(input_file);
        String encode = new String(strenc, "UTF-8");
        return encode;
    }


}
