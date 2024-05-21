package fpt.signature.sign.service.impl;

import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.dto.AuthenResponseDto;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.ex.CodeException;
import fpt.signature.sign.repository.UserCmsRepository;
import fpt.signature.sign.security.TokenCustomerProvider;
import fpt.signature.sign.service.AuthenService;
import fpt.signature.sign.utils.HttpRequestUtils;
import fpt.signature.sign.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenServiceImpl implements AuthenService {

    private final UserCmsRepository userCmsRepository;

    private final TokenCustomerProvider tokenCustomerProvider;

    private final Logger LOG = LoggerFactory.getLogger(AuthenServiceImpl.class);

    public AuthenServiceImpl(UserCmsRepository userCmsRepository, TokenCustomerProvider tokenCustomerProvider) {
        this.userCmsRepository = userCmsRepository;
        this.tokenCustomerProvider = tokenCustomerProvider;
    }


    @Override
    public AuthenResponseDto authUserCMS(CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp", date);
        try {
            if (Utils.isNullOrEmpty(dto.getUsername()) || Utils.isNullOrEmpty(dto.getPassword())) {
                LOG.error("username or password cannot is null, empty.");
                throw new CodeException(1002);
            }
            UserCms user = userCmsRepository.findByUsername(dto.getUsername());
            if (user == null) throw new CodeException(101);
            if (!user.isEnabled()) throw new CodeException(102);
            String passDB = user.getPassword();
            if (!dto.getPassword().equals(passDB)) {
                throw new CodeException(103);
            }
            Map<String, Object> claim = new HashMap<>();
            claim.put("user_cms", user.getUsername());
            String access_token = tokenCustomerProvider.createToken("webapp", claim, false);
            String refresh_token = tokenCustomerProvider.createToken("webapp", claim, true);
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(0);
            authenResponseDto.setCodeDesc("SUCCESS!");
            authenResponseDto.setAccess_token(access_token);
            authenResponseDto.setRefresh_token(refresh_token);
            authenResponseDto.setTimestamp(date);
            authenResponseDto.setResponse_billcode(billcode);
            return authenResponseDto;
        } catch (CodeException var1) {
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(var1.getResponsecode());
            authenResponseDto.setCodeDesc("");
            return authenResponseDto;
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error(e.getMessage());
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(1003);
            return authenResponseDto;
        }
    }

    @Override
    public AuthenResponseDto reAuthUserCMS(CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("CMS", date);
        try {
            if (Utils.isNullOrEmpty(dto.getRefreshtoken())) {
                LOG.error("refresh token is null.");
                throw new CodeException(1002);
            }
            if (!tokenCustomerProvider.isValidToken(dto.getRefreshtoken())) {
                LOG.error("valid refresh_token is invalid.");
                throw new CodeException(104);
            }
            if (tokenCustomerProvider.checkTokenIsExpired(dto.getRefreshtoken())) {
                LOG.error("valid refresh_token is expried.");
                throw new CodeException(106);
            }
            Map claims = tokenCustomerProvider.extractClaimAll(dto.getRefreshtoken());

            String access_token = tokenCustomerProvider.createToken("webapp", claims, false);
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(0);
            authenResponseDto.setCodeDesc("SUCCESS!");
            authenResponseDto.setAccess_token(access_token);
            authenResponseDto.setTimestamp(date);
            authenResponseDto.setResponse_billcode(billcode);
            return authenResponseDto;
        } catch (CodeException var1) {
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(var1.getResponsecode());
            authenResponseDto.setCodeDesc("");
            return authenResponseDto;
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error(e.getMessage());
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(1003);
            return authenResponseDto;
        }
    }

    @Override
    public AuthenResponseDto validTokenUserCMS(HttpServletRequest request) {
        try {
            HashMap<String, String> authenticationHeaders = HttpRequestUtils.getAuthenticationHeaders(request);

            if (!authenticationHeaders.containsKey("Authorization") && !authenticationHeaders.containsKey("authorization")) {
                LOG.error("request header Authorization is not found");
                throw new CodeException(1001);
            }
            String authorizationData = (authenticationHeaders.get("authorization") != null)
                    ? authenticationHeaders.get("authorization")
                    : authenticationHeaders.get("Authorization");
            if (Utils.isNullOrEmpty(authorizationData)) {
                LOG.error("Authorization cannot be NULL or EMPTY in request header");
                throw new CodeException(1001);
            }
            if (authorizationData.indexOf("Bearer ") != 0) {
                LOG.error("Bearer token cannot be NULL or EMPTY in Authorization");
                throw new CodeException(5006);
            }
            String token = authorizationData.substring("Bearer ".length());
            if (!tokenCustomerProvider.isValidToken(token)) {
                LOG.error("Bearer token is invalid");
                throw new CodeException(5006);
            }
            if (tokenCustomerProvider.checkTokenIsExpired(token)) {
                LOG.error("Bearer token is EXPIRED");
                throw new CodeException(5007);
            }
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(0);
            authenResponseDto.setCodeDesc("SUCCESSFULLY");
            authenResponseDto.setAccess_token(token);
            return authenResponseDto;
        } catch (CodeException var1) {
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(var1.getResponsecode());
            authenResponseDto.setCodeDesc("ERROR");
            return authenResponseDto;
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error(e.getMessage());
            AuthenResponseDto authenResponseDto = new AuthenResponseDto();
            authenResponseDto.setCode(1003);
            return authenResponseDto;
        }
    }
}
