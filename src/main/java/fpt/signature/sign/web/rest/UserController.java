package fpt.signature.sign.web.rest;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RestController
@RequestMapping("/web")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/profile")
    public ResponseEntity<?> accountProfile(@Context HttpServletRequest request) throws Exception {
        CMSResponse response = userService.getProfile(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/user/change_password")
    public ResponseEntity<?> changePassUser(@RequestBody CmsDto dto, @Context HttpServletRequest request) throws Exception {
        CMSResponse response = userService.changePass(dto, request);
        return ResponseEntity.ok(response);
    }
}
