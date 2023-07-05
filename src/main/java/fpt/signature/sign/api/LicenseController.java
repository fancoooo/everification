package fpt.signature.sign.api;

import fpt.signature.sign.api.request.SignPDFRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.license.LicenseManager;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.utils.Base64Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/rest/esignature"})
public class LicenseController {

    @RequestMapping(
            value = {"/generateRequest"},
            method = {RequestMethod.GET},
            headers = {"Content-Type=application/json"}
    )
    public BaseResponse generateRequest() {
        BaseResponse response = new BaseResponse();

        try {
            response.setResponseCode(1);
            response.setError(false);
            String r = LicenseManager.generateRequest("1.0.0", "eSignature");
            response.setResponseMessage(r);
        } catch (Exception var6) {
            response.setResponseCode(0);
            response.setError(true);
            response.setResponseMessage("Lỗi khi ký số : " + var6.getMessage());
        }
        return response;
    }
}
