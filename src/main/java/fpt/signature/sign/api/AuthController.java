package fpt.signature.sign.api;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import fpt.signature.sign.api.request.OcrRequest;
import fpt.signature.sign.api.response.BaseResponse;
import fpt.signature.sign.auth.AuthRequest;
import fpt.signature.sign.auth.UsersToken;
import fpt.signature.sign.aws.AWSCall;
import fpt.signature.sign.aws.datatypes.PadesConstants;
import fpt.signature.sign.object.InternalResponse;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@RestController
@RequestMapping({"/users/auth"})
public class AuthController {

    @RequestMapping(
            value = {"/login"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )

    public InternalResponse login(@RequestBody AuthRequest req, @Context HttpServletRequest request) throws Exception {

        InternalResponse response = new UsersToken().Get(req, request);

        return response;
    }

    @RequestMapping(
            value = {"/info"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public InternalResponse info(@Context HttpServletRequest request) throws Exception {
        InternalResponse response = new UsersToken().veriry(request);
        return response;
    }
}
