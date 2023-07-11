package fpt.signature.sign.api;

import fpt.signature.sign.api.request.SignPDFRequest;
import fpt.signature.sign.api.request.VerifyPDFRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.license.LicenseManager;
import fpt.signature.sign.object.VerifyResult;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.service.IEVerifyService;
import fpt.signature.sign.utils.Base64Utils;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping({"/api/everify"})
public class eVerifyController {
    @Autowired
    private IEVerifyService eVerifyService;

    @RequestMapping(
            value = {"/verifypdf"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public BaseResponse signPdf(@RequestBody VerifyPDFRequest req) {
        BaseResponse response = new BaseResponse();


        try {
            response.setResponseCode(1);
            response.setError(false);

            List<VerifyResult> dataSigned = this.eVerifyService.verifyPdf(Base64Utils.base64Decode(req.getSigningFileData()));
            response.setSignatureDetail(dataSigned);
            response.setResponseMessage("Thành công");
        }
        catch (Exception var6) {
            response.setResponseCode(0);
            response.setError(true);
            response.setResponseMessage("Lỗi khi verify : " + var6.getMessage());
            var6.printStackTrace();
        }
        return response;
    }
}
