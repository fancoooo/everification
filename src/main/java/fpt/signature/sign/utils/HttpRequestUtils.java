package fpt.signature.sign.utils;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.HashMap;

public class HttpRequestUtils {

    public static String getIP(HttpServletRequest request){
        return request.getRemoteAddr();
    }

    public static HashMap<String, String> getAuthenticationHeaders(HttpServletRequest request) {
        HashMap<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = headerNames.nextElement();
            String value = request.getHeader(key);
            headers.put(key, value);
        }
        return headers;
    }

    public boolean isUseSSL(HttpServletRequest request) {
        if (request.getScheme().indexOf("https") == 0)
            return true;
        return false;
    }

    public static String getRequestHeader(HttpServletRequest request, String headerName) {
        String headerValue = null;
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = headerNames.nextElement();
            headerValue = request.getHeader(key);
            if (key.compareToIgnoreCase(headerName) == 0)
                return headerValue;
            headerValue = null;
        }
        return headerValue;
    }
}
