package fpt.signature.sign.api;

import fpt.signature.sign.auth.AuthRequest;
import fpt.signature.sign.auth.UsersToken;
import fpt.signature.sign.database.DatabaseImp;
import fpt.signature.sign.object.InternalResponse;
import fpt.signature.sign.tsa.TimstampTokenService;
import fpt.signature.sign.tsa.TsaRequest;
import fpt.signature.sign.tsa.TsaResponse;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import java.util.Calendar;
import java.util.Date;

@RestController
@RequestMapping({"/api"})
public class TSAController {

    private static final Logger LOG = Logger.getLogger(TSAController.class);

    @RequestMapping(
            value = {"/GetTimeStampToken"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    
    public ResponseEntity<TsaResponse> GetTimestampToken(@RequestBody TsaRequest req, @Context HttpServletRequest request) throws Exception {
        Date time_request = Calendar.getInstance().getTime();

        TsaResponse response = new TimstampTokenService().getToken(req, request);

        HttpStatus status = HttpStatus.OK;
        switch (response.getResponseCode()){
            case 201:
            case 208:
            case 209:
                status = HttpStatus.BAD_REQUEST;
                break;
            case 207:
                status = HttpStatus.UNAUTHORIZED;
                break;
            case 203:
                status = HttpStatus.INTERNAL_SERVER_ERROR;
                break;
        }

        Date time_response = Calendar.getInstance().getTime();
        DatabaseImp db = new DatabaseImp();
        if(!db.insert_bct_tsa_log(req.content.transactionId, Utils.toJSONString(req),
                Utils.toJSONString(response), String.valueOf(status.value()),
                request.getRemoteAddr(), time_request, time_response, Utils.getRequestHeader(request, "X-API-KEY"))){
            LOG.debug("Call [SQL: insert_bct_tsa_log] ERROR");
        }

        return ResponseEntity.status(status).body(response);
    }

}
