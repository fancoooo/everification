package fpt.signature.sign.web.rest;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.service.RelyingPartyService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping("/web")
public class RelyingPartyController {

    private final RelyingPartyService relyingPartyService;

    public RelyingPartyController(RelyingPartyService relyingPartyService) {
        this.relyingPartyService = relyingPartyService;
    }

    @GetMapping("/relying_party/list")
    public ResponseEntity<?> listRelyingParty(@Context HttpServletRequest request) {
        CMSResponse response = relyingPartyService.listOfRelyingParty(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/relying_party/create")
    public ResponseEntity<?> createRelyingParty(@RequestBody CmsDto dto , @Context HttpServletRequest request) {
        CMSResponse response = relyingPartyService.createRelyingParty(dto, request);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/relying_party/edit/{id}")
    public ResponseEntity<?> editRelyingParty(@PathVariable Long id,@RequestBody CmsDto dto ,@Context HttpServletRequest request) {
        CMSResponse response = relyingPartyService.editRelyingParty(id, dto, request);
        return ResponseEntity.ok(response);
    }
}
