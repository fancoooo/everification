package fpt.signature.sign.service;

import fpt.signature.sign.domain.VerificationLog;
import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;

import javax.servlet.http.HttpServletRequest;

public interface VerificationLogService {
    CMSResponse listOfLog(HttpServletRequest request);
    void insertLog(VerificationLog verificationLog);
}
