package fpt.signature.sign.api;

import fpt.signature.sign.auth.EverificationToken;
import fpt.signature.sign.database.DatabaseImp;
import fpt.signature.sign.domain.RelyingParty;
import fpt.signature.sign.domain.VerificationLog;
import fpt.signature.sign.everification.EverificationService;
import fpt.signature.sign.everification.objects.RequestJSNObject;
import fpt.signature.sign.everification.objects.VerificationInternalResponse;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.object.InternalResponse;
import fpt.signature.sign.service.VerificationLogService;
import fpt.signature.sign.utils.Utils;
import org.springframework.context.annotation.DependsOn;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import java.util.Calendar;
import java.util.Date;

@RestController
@RequestMapping({"/api/everify"})
public class eVerifyController {

    private final EverificationToken everificationToken;

    private final EverificationService everificationService;

    private final VerificationLogService verificationLogService;


    public eVerifyController(EverificationToken everificationToken, EverificationService everificationService, VerificationLogService verificationLogService) {
        this.everificationToken = everificationToken;
        this.everificationService = everificationService;
        this.verificationLogService = verificationLogService;
    }

    @RequestMapping(
            value = {"/pdf"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public VerificationInternalResponse verifyPAdES(@RequestBody RequestJSNObject req, @Context HttpServletRequest request) throws Exception {
        String function = "/api/everify/pdf";
        Date time_request = Calendar.getInstance().getTime();
        InternalResponse resToken = everificationToken.verify(request, function);

        VerificationInternalResponse res = null;
        if(resToken.getStatus() == 0){
            res = everificationService.verifyPdf(req, resToken.getRp());
        } else res = new VerificationInternalResponse(resToken.getStatus(), resToken.getMessage());
        Date time_response = Calendar.getInstance().getTime();
        VerificationLog verificationLog = new VerificationLog();
        verificationLog.setFunctionName(function);
        verificationLog.setRequestBillcode(req.getRequest_bill_code());
        verificationLog.setResponseBillcode(res.getResponse_bill_code());
        if(resToken.getRp() != null)
            verificationLog.setRelyingParty(RelyingParty.builder().id((long) resToken.getRp().getId()).build());
        else verificationLog.setRelyingParty(null);
        verificationLog.setRequestData(Utils.cutoffBigDataInJson(Utils.toJSONString(req), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
        verificationLog.setResponseData(Utils.cutoffBigDataInJson(Utils.toJSONString(res), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
        verificationLog.setRequestIp(request.getRemoteAddr());
        verificationLog.setResponseCode(Resources.getResponseCodes().get(res.getStatus() + ""));
        verificationLog.setTimeRequest(time_request);
        verificationLog.setTimeResponse(time_response);
        verificationLogService.insertLog(verificationLog);
        return res;
    }
    @RequestMapping(
            value = {"/xml"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public VerificationInternalResponse verifyXades(@RequestBody RequestJSNObject req, @Context HttpServletRequest request) throws Exception {
        String function = "/api/everify/xml";
        Date time_request = Calendar.getInstance().getTime();
        InternalResponse resToken = everificationToken.verify(request, function);
        VerificationInternalResponse res = null;
        if(resToken.getStatus() == 0){
            res = everificationService.verifyXml(req, resToken.getRp());
        } else res = new VerificationInternalResponse(resToken.getStatus(), resToken.getMessage());
        Date time_response = Calendar.getInstance().getTime();
        if(resToken.getRp() != null){
            VerificationLog verificationLog = new VerificationLog();
            verificationLog.setFunctionName(function);
            verificationLog.setRequestBillcode(req.getRequest_bill_code());
            verificationLog.setResponseBillcode(res.getResponse_bill_code());
            if(resToken.getRp() != null)
                verificationLog.setRelyingParty(RelyingParty.builder().id((long) resToken.getRp().getId()).build());
            else verificationLog.setRelyingParty(null);
            verificationLog.setRequestData(Utils.cutoffBigDataInJson(Utils.toJSONString(req), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
            verificationLog.setResponseData(Utils.cutoffBigDataInJson(Utils.toJSONString(res), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
            verificationLog.setRequestIp(request.getRemoteAddr());
            verificationLog.setResponseCode(Resources.getResponseCodes().get(res.getStatus() + ""));
            verificationLog.setTimeRequest(time_request);
            verificationLog.setTimeResponse(time_response);
            verificationLogService.insertLog(verificationLog);
        }
        return res;
    }
    @RequestMapping(
            value = {"/office"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public VerificationInternalResponse verifyoffice(@RequestBody RequestJSNObject req, @Context HttpServletRequest request) throws Exception {
        String function = "/api/everify/office";
        Date time_request = Calendar.getInstance().getTime();
        InternalResponse resToken = everificationToken.verify(request, function);
        VerificationInternalResponse res = null;
        if(resToken.getStatus() == 0){
            res = everificationService.verifyOffice(req, resToken.getRp());
        } else res = new VerificationInternalResponse(resToken.getStatus(), resToken.getMessage());
        Date time_response = Calendar.getInstance().getTime();
        if(resToken.getRp() != null){
            VerificationLog verificationLog = new VerificationLog();
            verificationLog.setFunctionName(function);
            verificationLog.setRequestBillcode(req.getRequest_bill_code());
            verificationLog.setResponseBillcode(res.getResponse_bill_code());
            if(resToken.getRp() != null)
                verificationLog.setRelyingParty(RelyingParty.builder().id((long) resToken.getRp().getId()).build());
            else verificationLog.setRelyingParty(null);
            verificationLog.setRequestData(Utils.cutoffBigDataInJson(Utils.toJSONString(req), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
            verificationLog.setResponseData(Utils.cutoffBigDataInJson(Utils.toJSONString(res), Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE));
            verificationLog.setRequestIp(request.getRemoteAddr());
            verificationLog.setResponseCode(Resources.getResponseCodes().get(res.getStatus() + ""));
            verificationLog.setTimeRequest(time_request);
            verificationLog.setTimeResponse(time_response);
            verificationLogService.insertLog(verificationLog);
        }
        return res;
    }
}
