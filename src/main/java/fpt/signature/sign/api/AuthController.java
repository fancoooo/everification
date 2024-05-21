package fpt.signature.sign.api;

import fpt.signature.sign.auth.AuthRequest;
import fpt.signature.sign.auth.AuthVerificationRequest;
import fpt.signature.sign.auth.EverificationToken;
import fpt.signature.sign.auth.UsersToken;
import fpt.signature.sign.object.InternalResponse;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping({"/users/auth"})
public class AuthController {

    private final EverificationToken everificationToken;

    public AuthController(EverificationToken everificationToken) {
        this.everificationToken = everificationToken;
    }

    @RequestMapping(
            value = {"/token"},
            method = {RequestMethod.POST},
            headers = {"Content-Type=application/json"}
    )
    public InternalResponse token(@RequestBody AuthVerificationRequest req, @Context HttpServletRequest request) throws Exception {
        return everificationToken.create(req, request);
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
