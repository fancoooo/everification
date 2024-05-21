package fpt.signature.sign.service.impl;

import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.dto.UserCMSDto;
import fpt.signature.sign.ex.CodeException;
import fpt.signature.sign.repository.UserCmsRepository;
import fpt.signature.sign.service.UserService;
import fpt.signature.sign.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Service
public class UserServiceImpl implements UserService {

    private final static Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserCmsRepository userCmsRepository;

    public UserServiceImpl(UserCmsRepository userCmsRepository) {
        this.userCmsRepository = userCmsRepository;
    }

    @Override
    public CMSResponse getProfile(HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp",date);
        try {
            UserCms userBO = (UserCms) request.getAttribute("user");
            UserCMSDto info = new UserCMSDto();
            info.setUsername(userBO.getUsername());
            info.setId(userBO.getId());
            info.setFull_name(userBO.getName());
            info.setCreate_date(userBO.getCreatedDt());
            CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
            cmsResponse.setUser_info(info);
            return cmsResponse;
        } catch (Exception var) {
            log.error(var.getMessage());
            Utils.printStackTrace(var);
            return new CMSResponse(1003, "ERROR", billcode, date);
        }
    }


    @Override
    public CMSResponse changePass(CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp", date);
        try {
            UserCms user = (UserCms) request.getAttribute("user");
            if (Utils.isNullOrEmpty(dto.getNewPassword()) || Utils.isNullOrEmpty(dto.getOldPassword())) {
                throw new CodeException(1002);
            }
            if (!user.getPassword().equals(dto.getOldPassword())) {
                throw new CodeException(108);
            }
            user.setPassword(dto.getNewPassword());
            userCmsRepository.save(user);
            CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
            return cmsResponse;
        } catch (CodeException e) {
            return new CMSResponse(
                    e.getResponsecode(),
                    "ERROR",
                    billcode,
                    date
            );
        }
    }
}
