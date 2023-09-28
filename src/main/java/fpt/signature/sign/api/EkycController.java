package fpt.signature.sign.api;

import fpt.signature.sign.api.request.OcrRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.aws.AWSCall;
import fpt.signature.sign.aws.datatypes.PadesConstants;
import fpt.signature.sign.license.LicenseManager;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.MalformedURLException;

@RestController
@RequestMapping({"/rest/esignature"})
public class EkycController {

    @RequestMapping(
            value = {"/ocr"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public BaseResponse generateRequest(@RequestBody OcrRequest req) throws IOException {
        BaseResponse response = new BaseResponse();
        String methodName = "POST";
        String accessKey = "VW7SYCJVTUJZFADIEEE3";
        String secretKey = "Ha2dTIChzVoqnE8EdOatuChPNLyuk1MEFAGqB1W8";
        String regionName = "vn-south-1";
        String serviceName = "dtis-20.10.05";
        int timeOut = 3000;
        String xApiKey = "SARLUv9uuzoHdCJNRN1dXT-quzeLMmvMrsaTioPk";
        String contentType = "application/json";
        String sessionToken = "Basic SVNBUFA6SGEyZFRJQ2h6Vm9xbkU4RWRPYXR1Q2hQTkx5dWsxTUVGQUdxQjFXOA==";

        AWSCall aWSCallGetToken = new AWSCall(
                "GET",
                accessKey,
                secretKey,
                regionName,
                serviceName,
                timeOut,
                xApiKey,
                contentType);

        AWSCall aWSCallPades = new AWSCall(
                methodName,
                accessKey,
                secretKey,
                regionName,
                serviceName,
                timeOut,
                xApiKey,
                contentType);

        aWSCallGetToken.v1VeriOidcToken(PadesConstants.V1_EVERIFICATION_OIDC_TOKEN, sessionToken);

        return response;
    }
}
