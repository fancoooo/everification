package fpt.signature.sign.api;

import fpt.signature.sign.api.request.SignPDFRequest;
import fpt.signature.sign.api.request.VerifyPDFRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.everification.core.PAdESVerificationItext7;
import fpt.signature.sign.everification.core.XAdESVerification;
import fpt.signature.sign.everification.objects.RequestJSNObject;
import fpt.signature.sign.everification.objects.VerificationInternalResponse;
import fpt.signature.sign.license.LicenseManager;
import fpt.signature.sign.object.VerifyResult;
import fpt.signature.sign.service.IESignatureService;
import fpt.signature.sign.service.IEVerifyService;
import fpt.signature.sign.utils.Base64Utils;
import fpt.signature.sign.utils.Utils;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
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

    @RequestMapping(
            value = {"/pdf"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public VerificationInternalResponse verifyPAdES(@RequestBody RequestJSNObject req, @Context HttpServletRequest request){
        try{
            if(req == null){
                return new VerificationInternalResponse(201, "Dữ liệu không hợp lệ");
            }

            if(Utils.isNullOrEmpty(req.getDocument())){
                return new VerificationInternalResponse(202, "Dữ liệu pdf không hợp lệ");
            }

            byte[] document = Base64Utils.base64Decode(req.getDocument());



            return new PAdESVerificationItext7().verify(document, req.getPassword(), false, 0, null, null, null);
        }catch (Exception ex){
            return new VerificationInternalResponse(203, "UNKNOW EXCEPTION");
        }

    }


    @RequestMapping(
            value = {"/xml"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public VerificationInternalResponse verifyXades(@RequestBody RequestJSNObject req, @Context HttpServletRequest request){
        try{
            if(req == null){
                return new VerificationInternalResponse(201, "Dữ liệu không hợp lệ");
            }

            if(Utils.isNullOrEmpty(req.getDocument())){
                return new VerificationInternalResponse(202, "Dữ liệu pdf không hợp lệ");
            }

            byte[] document = Base64Utils.base64Decode(req.getDocument());



            return new XAdESVerification().verify(document);
        }catch (Exception ex){
            return new VerificationInternalResponse(203, "UNKNOW EXCEPTION");
        }

    }


}
