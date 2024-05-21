package fpt.signature.sign.api;

import fpt.signature.sign.general.Resources;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/system/"})
public class SystemController {
    @RequestMapping(
            value = {"/reload/resource"},
            method = {RequestMethod.GET}
    )
    public void ReloadResource(){
        Resources.reloadRP();
    }


}
