package fpt.signature.sign.service;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;

import javax.servlet.http.HttpServletRequest;

public interface UserService {
    CMSResponse getProfile(HttpServletRequest request);
    CMSResponse changePass(CmsDto dto, HttpServletRequest request);
}
