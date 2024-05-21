package fpt.signature.sign.service;

import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;

import javax.servlet.http.HttpServletRequest;

public interface CertificateAuthorityService {
    CMSResponse list(HttpServletRequest request);
    CMSResponse create(CmsDto dto, HttpServletRequest request);
    CMSResponse edit(Long id, CmsDto dto, HttpServletRequest request);
}
