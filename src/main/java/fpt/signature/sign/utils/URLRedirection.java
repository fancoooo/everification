package fpt.signature.sign.utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

import org.apache.log4j.Logger;
import org.jsoup.Connection;
import org.jsoup.Jsoup;

public class URLRedirection {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.utils.URLRedirection.class);

    static {
        disableSslVerification();
    }

    public String getUrl(String url) {
        String redirectUrl = url;
        if (Utils.isNullOrEmpty(url))
            return null;
        try {
            Connection.Response response = Jsoup.connect(url).followRedirects(false).ignoreContentType(true).sslSocketFactory(socketFactory()).execute();
            if (response.hasHeader("location")) {
                redirectUrl = response.header("location");
                LOG.debug("URL redirection detected. Redirect to " + redirectUrl);
                getUrl(redirectUrl);
            } else {
                LOG.debug("URL redirection finished. Use url " + redirectUrl);
            }
        } catch (IOException e) {
            e.printStackTrace();
            LOG.error("Error while checking URL redirection. Details: " + Utils.printStackTrace(e));
        }
        return redirectUrl;
    }

    private SSLSocketFactory socketFactory() {
        TrustManager[] trustAllCerts = new TrustManager[]{new $1(this)};
        try {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory result = sslContext.getSocketFactory();
            return result;
        } catch (NoSuchAlgorithmException|KeyManagementException e) {
            throw new RuntimeException("Failed to create a SSL socket factory", e);
        }
    }

    public static void disableSslVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
            }};
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init((KeyManager[])null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HostnameVerifier allHostsValid = new javax.net.ssl.HostnameVerifier() {
                public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException var3) {
            var3.printStackTrace();
        } catch (KeyManagementException var4) {
            var4.printStackTrace();
        }

    }

    class $1 implements X509TrustManager {

        final URLRedirection this$0;

        $1(URLRedirection this$0) {
            this.this$0 = this$0;
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }

}

