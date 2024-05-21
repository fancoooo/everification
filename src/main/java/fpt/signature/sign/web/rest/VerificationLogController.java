package fpt.signature.sign.web.rest;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.service.VerificationLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping("/web")
public class VerificationLogController {

    private final VerificationLogService verificationLogService;

    public VerificationLogController(VerificationLogService verificationLogService) {
        this.verificationLogService = verificationLogService;
    }

    @GetMapping("/verification_log/list")
    public ResponseEntity<?> listRelyingParty(@Context HttpServletRequest request) {
        CMSResponse response = verificationLogService.listOfLog(request);
        return ResponseEntity.ok(response);
    }
}
