package fpt.signature.sign.service;

import fpt.signature.sign.dto.AuthenResponseDto;
import fpt.signature.sign.dto.CmsDto;

import javax.servlet.http.HttpServletRequest;

public interface AuthenService {
    AuthenResponseDto authUserCMS(CmsDto dto, HttpServletRequest request);
    AuthenResponseDto reAuthUserCMS(CmsDto dto, HttpServletRequest request);
    AuthenResponseDto validTokenUserCMS(HttpServletRequest request);
}
