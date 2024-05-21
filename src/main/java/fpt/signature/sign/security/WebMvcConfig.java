package fpt.signature.sign.security;

import fpt.signature.sign.repository.UserCmsRepository;
import fpt.signature.sign.service.AuthenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthenService authenService;
    private final UserCmsRepository userCmsRepository;
    private final TokenCustomerProvider tokenCustomerProvider;

    public WebMvcConfig(AuthenService authenService, UserCmsRepository userCmsRepository, TokenCustomerProvider tokenCustomerProvider) {
        this.authenService = authenService;
        this.userCmsRepository = userCmsRepository;
        this.tokenCustomerProvider = tokenCustomerProvider;
    }


    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry
                .addInterceptor(new CustomInterceptorCMS(authenService, tokenCustomerProvider, userCmsRepository))
                .addPathPatterns("/web/**").excludePathPatterns("/web/user/login", "/web/user/relogin");
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:4200", "http://10.14.185.3", "http://10.14.185.3:4200", "http://localhost", "http://localhost:61743"));
        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PUT","OPTIONS","PATCH", "DELETE"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setExposedHeaders(Arrays.asList("Authorization"));
//        if (!CollectionUtils.isEmpty(config.getAllowedOrigins()) || !CollectionUtils.isEmpty(config.getAllowedOriginPatterns())) {
//            log.debug("Registering CORS filter");
        //config = config.setAllowedOrigins("*");
        source.registerCorsConfiguration("/web/**", corsConfiguration);
        source.registerCorsConfiguration("/api/**", corsConfiguration);
        source.registerCorsConfiguration("/cms/**", corsConfiguration);
        source.registerCorsConfiguration("/management/**", corsConfiguration);
        source.registerCorsConfiguration("/v3/api-docs", corsConfiguration);
        source.registerCorsConfiguration("/swagger-ui/**", corsConfiguration);
        //}
        return new CorsFilter(source);
    }
}
