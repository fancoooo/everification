package fpt.signature.sign.service;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;

import javax.servlet.http.HttpServletRequest;

public interface RelyingPartyService {
    CMSResponse generateP12(CmsDto dto, HttpServletRequest request) throws Exception;
    CMSResponse createRelyingParty(CmsDto dto, HttpServletRequest request);
    CMSResponse editRelyingParty(Long id, CmsDto dto, HttpServletRequest request);
    CMSResponse listOfRelyingParty(HttpServletRequest request);
}
