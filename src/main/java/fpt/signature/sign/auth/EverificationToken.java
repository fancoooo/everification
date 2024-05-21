package fpt.signature.sign.auth;

import com.mysql.cj.log.Log;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import fpt.signature.sign.general.RelyingParty;
import fpt.signature.sign.general.Resources;
import fpt.signature.sign.object.InternalResponse;
import fpt.signature.sign.security.TokenCustomerProvider;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class EverificationToken {

    private final Logger LOG = Logger.getLogger(fpt.signature.sign.auth.AuthVerificationRequest.class);

    private final TokenCustomerProvider tokenCustomerProvider;
    private final Resources resources;

    public EverificationToken(TokenCustomerProvider tokenCustomerProvider, Resources resources) {
        this.tokenCustomerProvider = tokenCustomerProvider;
        this.resources = resources;
    }

    public InternalResponse create(AuthVerificationRequest req, HttpServletRequest request) throws Exception {
        String RPName = req.getRp_id();
        if(!Utils.isNullOrEmpty(req.getRp_id())){
            RelyingParty rp = Resources.getRelyingPartyByName().get(RPName);
            if(rp == null) {
                resources.reloadRP();
                rp = Resources.getRelyingPartyByName().get(RPName);
            }
            if(rp == null){
                LOG.error("Invalid credentials. No relying party " + RPName + " found");
                return new InternalResponse(1001, "CREDENTIAL IS INVALID", null);
            }

            String pwDB = Utils.printHexBinary(Utils.calcHmacSha256(rp.getAuthProperties().getAccess().getBytes(), rp.getAuthProperties().getText().getBytes()));
            if(!req.getRp_pw().toUpperCase().equals(pwDB)){
                LOG.error("Invalid credentials. relying party " + RPName +":  password is invalid");
                return new InternalResponse(1001, "CREDENTIAL IS INVALID", null);
            }
        }else{
            LOG.error("Invalid credentials. relying party is empty");
            return new InternalResponse(1001, "CREDENTIAL IS INVALID", null);
        }
        Map<String, Object> claim = new HashMap<>();
        claim.put("rp", RPName);
        String accessToken = tokenCustomerProvider.createToken("tse", claim, false);
        return new InternalResponse(0, "SUCCESSFULLY", accessToken, "Bearer", 3600, null);
    }

    public InternalResponse verify(HttpServletRequest request, String function) throws Exception {
        String Brear = Utils.getRequestHeader(request,"Authorization");
        if(!Utils.isNullOrEmpty(Brear)){
            String accessToken = Utils.getRequestHeader(request,"Authorization").substring(7);
            if(Utils.isNullOrEmpty(accessToken)){
                LOG.error("Invalid credentials. bearerToken is null");
                return new InternalResponse(3005, "BEARER TOKEN IS INVALID",null);
            }
            try{
                if (!tokenCustomerProvider.isValidToken(accessToken)) {
                    LOG.error("Invalid credentials. bearerToken is verify exception");
                    return new InternalResponse(3005, "BEARER TOKEN IS INVALID", null);
                }
                String rp_name = tokenCustomerProvider.extractClaim(accessToken, "rp");
                RelyingParty rp = Resources.getRelyingPartyByName().get(rp_name);
                if(rp == null){
                    LOG.error("Invalid credentials. No relying party " + rp_name + " found");
                    return new InternalResponse(3005, "BEARER TOKEN IS INVALID", rp);
                }
                if (tokenCustomerProvider.checkTokenIsExpired(accessToken)) {
                    return new InternalResponse(3006, "BEARER TOKEN IS ALREADY EXPIRED", rp);
                }
                if(!Utils.ipcheck(rp.getVerificationIPRestriction(), request.getRemoteAddr())){
                    LOG.error("Access from RP " + rp.getName() + " denied due to invalid IP " + request.getRemoteAddr());
                    return new InternalResponse(5003, "IP ADDRESS IS INVALID", rp);
                }
                if(!Utils.funccheck(rp.getFunctionAccessList(), function)){
                    LOG.error("Access from RP " + rp.getName() + " denied due to function is not allowed to use (function: " + function + ")");
                    return new InternalResponse(5005, "FUNCTION IS NOT ACCESSED", rp);
                }
                return new InternalResponse(0, "SUCCESSFULLY", null, null, 0, rp);
            }catch (Exception var){
                LOG.error("Exception while parsing JWT", var);
                return new InternalResponse(3005, "BEARER TOKEN IS INVALID", null);
            }
        }else{
            return new InternalResponse(3005, "BEARER TOKEN IS INVALID", null);
        }
    }
}
