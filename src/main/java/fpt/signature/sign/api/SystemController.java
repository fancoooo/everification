package fpt.signature.sign.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import fpt.signature.sign.general.Resources;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/system/"})
public class SystemController {

    private final Resources resources;

    public SystemController(Resources resources) {
        this.resources = resources;
    }

    @RequestMapping(
            value = {"/reload/resource"},
            method = {RequestMethod.GET}
    )
    public void ReloadResource() throws JsonProcessingException {
        resources.reloadRP();
    }


}
