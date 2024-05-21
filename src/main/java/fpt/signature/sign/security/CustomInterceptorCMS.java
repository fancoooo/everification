package fpt.signature.sign.security;

import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.dto.AuthenResponseDto;
import fpt.signature.sign.repository.UserCmsRepository;
import fpt.signature.sign.service.AuthenService;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

public class CustomInterceptorCMS implements HandlerInterceptor {

    private final AuthenService authenService;
    private final TokenCustomerProvider tokenCustomerProvider;
    private final UserCmsRepository userCmsRepository;

    public CustomInterceptorCMS(
            AuthenService authenService,
            TokenCustomerProvider tokenCustomerProvider, UserCmsRepository userCmsRepository
    ) {
        this.authenService = authenService;
        this.tokenCustomerProvider = tokenCustomerProvider;
        this.userCmsRepository = userCmsRepository;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        AuthenResponseDto auth = authenService.validTokenUserCMS(request);
        if (auth.getCode() == 5006 || auth.getCode() == 5007 || auth.getCode() == 1001) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try (PrintWriter writer = response.getWriter()) {
                writer.println(auth.getCodeDesc());
            }
            return false;
        }

        String username = tokenCustomerProvider.extractClaim(auth.getAccess_token(), "user_cms");
        UserCms user = userCmsRepository.findByUsername(username);
        if (user == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try (PrintWriter writer = response.getWriter()) {
                writer.println("CREDENTIAL IS INVALID");
            }
            return false;
        }
        request.setAttribute("user", user);
        return true;
    }
}
