package fpt.signature.sign.web.rest;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.service.CertificateAuthorityService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping("/web")
public class CertificateAuthorityController {

    private final CertificateAuthorityService certificateAuthorityService;

    public CertificateAuthorityController(CertificateAuthorityService certificateAuthorityService) {
        this.certificateAuthorityService = certificateAuthorityService;
    }

    @GetMapping("/certificate_authority/list")
    public ResponseEntity<?> listCA(@Context HttpServletRequest request) throws Exception {
        CMSResponse response = certificateAuthorityService.list(request);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/certificate_authority/create")
    public ResponseEntity<?> createCA(@RequestBody CmsDto dto, @Context HttpServletRequest request) {
        CMSResponse response = certificateAuthorityService.create(dto, request);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/certificate_authority/edit/{id}")
    public ResponseEntity<?> editCA(@PathVariable Long id , @RequestBody CmsDto dto, @Context HttpServletRequest request) {
        CMSResponse response = certificateAuthorityService.edit(id ,dto, request);
        return ResponseEntity.ok(response);
    }
}
