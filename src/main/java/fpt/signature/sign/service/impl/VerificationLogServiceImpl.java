package fpt.signature.sign.service.impl;

import fpt.signature.sign.domain.RelyingParty;
import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.domain.VerificationLog;
import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.RelyingPartyDto;
import fpt.signature.sign.dto.VerificationLogDto;
import fpt.signature.sign.dto.mapper.VerificationLogMapper;
import fpt.signature.sign.repository.VerificationLogRepository;
import fpt.signature.sign.service.VerificationLogService;
import fpt.signature.sign.utils.Utils;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class VerificationLogServiceImpl implements VerificationLogService {

    private final VerificationLogRepository verificationLogRepository;


    public VerificationLogServiceImpl(VerificationLogRepository verificationLogRepository) {
        this.verificationLogRepository = verificationLogRepository;
    }

    @Override
    @Transactional
    public CMSResponse listOfLog(HttpServletRequest request) {
        Date date = new Date();
        String billCode = Utils.generateBillCode("webapp",date);
        UserCms user = (UserCms) request.getAttribute("user");
        List<VerificationLog> verificationLogs = verificationLogRepository.findAll();
        List<VerificationLogDto> verificationLogDtos = new ArrayList<>();
        for (VerificationLog verificationLog : verificationLogs) {
            VerificationLogDto verificationLogDto = new VerificationLogDto();
            verificationLogDto.setId(verificationLog.getId());
            verificationLogDto.setFunctionName(verificationLog.getFunctionName());
            verificationLogDto.setCreatedDt(verificationLog.getCreatedDt());
            verificationLogDto.setModifiedDt(verificationLog.getModifiedDt());
            verificationLogDto.setRequestBillcode(verificationLog.getRequestBillcode());
            verificationLogDto.setRelyingPartyId(verificationLog.getRelyingParty().getId());
            verificationLogDto.setRelyingPartyName(verificationLog.getRelyingParty().getName());
            verificationLogDto.setRequestData(verificationLog.getRequestData());
            verificationLogDto.setResponseCode("["+verificationLog.getResponseCode()+"] " + verificationLog.getResponseCode().getRemarkEn());
            verificationLogDto.setResponseData(verificationLog.getResponseData());
            verificationLogDto.setRequestIp(verificationLog.getRequestIp());
            verificationLogDto.setTimeRequest(Utils.convertDateToString(verificationLog.getTimeRequest(), "dd-MM-yyyy HH:mm:ss"));
            verificationLogDto.setTimeResponse(Utils.convertDateToString(verificationLog.getTimeResponse(), "dd-MM-yyyy HH:mm:ss"));
            verificationLogDtos.add(verificationLogDto);
        }
        CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billCode, date);
        cmsResponse.setVerification_logs(verificationLogDtos);
        return cmsResponse;
    }

    @Override
    @Async
    public void insertLog(VerificationLog verificationLog) {
        verificationLogRepository.save(verificationLog);
    }
}
