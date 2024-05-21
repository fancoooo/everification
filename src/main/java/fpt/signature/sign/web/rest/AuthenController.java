package fpt.signature.sign.web.rest;

import fpt.signature.sign.dto.AuthenResponseDto;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.service.AuthenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping("/web")
public class AuthenController {

    private final Logger log = LoggerFactory.getLogger(AuthenController.class);

    private final AuthenService authenService;

    public AuthenController(AuthenService authenService) {
        this.authenService = authenService;
    }

    @PostMapping("/user/login")
    public ResponseEntity<?> login(@RequestBody CmsDto dto, @Context HttpServletRequest request) throws Exception {
        AuthenResponseDto auth = authenService.authUserCMS(dto, request);
        return ResponseEntity.ok(auth);
    }

    @PostMapping("/user/relogin")
    public ResponseEntity<?> relogin(@RequestBody CmsDto dto, @Context HttpServletRequest request) throws Exception {
        AuthenResponseDto auth = authenService.reAuthUserCMS(dto, request);
        return ResponseEntity.ok(auth);
    }
}
