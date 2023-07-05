package fpt.signature.sign.api;

import fpt.signature.sign.api.request.SignPDFRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.license.LicenseManager;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.utils.Base64Utils;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping({"/rest/esignature"})
public class eSignatureController {
    @Autowired
    private IESignatureService eSignatureService;

    @RequestMapping(
            value = {"/signPdf"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public BaseResponse signPdf(@RequestBody SignPDFRequest req) {
        BaseResponse response = new BaseResponse();


        try {
            response.setResponseCode(1);
            response.setError(false);
            Boolean l = LicenseManager.checkLicense();
            if(l == false)
                throw new Exception("License invalid");
            String dataSigned = this.eSignatureService.signPdf(Base64Utils.base64Decode(req.getSigningFileData()));
            response.setSignedFileData(dataSigned);
            response.setResponseMessage("Ký số Thành công!");
        }catch (CryptoException e){
            response.setResponseCode(0);
            response.setError(true);
            response.setResponseMessage("Check license error: "+ e.getMessage());
        }
        catch (Exception var6) {
            response.setResponseCode(0);
            response.setError(true);
            response.setResponseMessage("Lỗi khi ký số : " + var6.getMessage());
        }
        return response;
    }
}
