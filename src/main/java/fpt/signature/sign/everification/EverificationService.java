package fpt.signature.sign.everification;

import fpt.signature.sign.everification.core.OfficeVerification;
import fpt.signature.sign.everification.core.PAdESVerificationItext7;
import fpt.signature.sign.everification.core.XAdESVerification;
import fpt.signature.sign.everification.objects.RequestJSNObject;
import fpt.signature.sign.everification.objects.VerificationInternalResponse;
import fpt.signature.sign.ex.NotFoundSignature;
import fpt.signature.sign.general.RelyingParty;
import fpt.signature.sign.utils.Base64Utils;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;

@Component
public class EverificationService {

    private final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.EverificationService.class);

    public VerificationInternalResponse verifyPdf(RequestJSNObject req, RelyingParty relyingParty){
        String billCode = Utils.generateTransactionId(relyingParty.getName(), Calendar.getInstance().getTime());
        try{
            if(req == null){
                LOG.error("request object is null");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            if(Utils.isNullOrEmpty(req.getDocument())){
                LOG.error("document is null or empty");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            byte[] document = Base64Utils.base64Decode(req.getDocument());
            return new PAdESVerificationItext7().verify(document, req.getPassword(), relyingParty, billCode);
        }catch (Exception ex){
            LOG.error("error occurred while verifying pdf", ex);
            return new VerificationInternalResponse(2003, null, billCode);
        }
    }

    public VerificationInternalResponse verifyXml(RequestJSNObject req, RelyingParty relyingParty){
        String billCode = Utils.generateTransactionId(relyingParty.getName(), Calendar.getInstance().getTime());
        try{
            if(req == null){
                LOG.error("request object is null");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            if(Utils.isNullOrEmpty(req.getDocument())){
                LOG.error("document is null or empty");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            byte[] document = Base64Utils.base64Decode(req.getDocument());
            return new XAdESVerification().verify(document, billCode);
        }catch (Exception ex){
            LOG.error("error occurred while verifying xml", ex);
            return new VerificationInternalResponse(2003, null, billCode);
        }
    }

    public VerificationInternalResponse verifyOffice(RequestJSNObject req, RelyingParty relyingParty){
        String billCode = Utils.generateTransactionId(relyingParty.getName(), Calendar.getInstance().getTime());
        try{
            if(req == null){
                LOG.error("request object is null");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            if(Utils.isNullOrEmpty(req.getDocument())){
                LOG.error("document is null or empty");
                return new VerificationInternalResponse(2001, null, billCode);
            }
            byte[] document = Base64Utils.base64Decode(req.getDocument());
            return new OfficeVerification().verify(document, req.getPassword(), billCode);
        }catch (Exception ex){
            LOG.error("error occurred while verifying office", ex);
            return new VerificationInternalResponse(2003, null, billCode);
        }
    }
}
