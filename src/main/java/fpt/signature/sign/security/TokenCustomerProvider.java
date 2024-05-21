package fpt.signature.sign.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import fpt.signature.sign.service.impl.FileResourceService;
import fpt.signature.sign.utils.Crypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Component
public class TokenCustomerProvider {

    private final Logger LOG = LoggerFactory.getLogger(TokenCustomerProvider.class);
    private final FileResourceService fileResourceService;

    @Value("${jwt.tse.expiration.access_token}")
    private long tse_expiration_access;

    @Value("${jwt.tse.expiration.refresh_token}")
    private long tse_expiration_refresh;

    @Value("${jwt.web_app.expiration.access_token}")
    private long webapp_expiration_access;

    @Value("${jwt.web_app.expiration.refresh_token}")
    private long webapp_expiration_refresh;

    @Value("${jwt.issuer}")
    private String issuer;

    public TokenCustomerProvider(FileResourceService fileResourceService) {
        this.fileResourceService = fileResourceService;
    }

    public String createToken(String module, Map<String, Object> claims, boolean isRemember) throws Exception {
        String privateKeyString = fileResourceService.readFileToString("private");
        if (privateKeyString == null) {
            throw new Exception("read file private key in resource error");
        }
        PrivateKey priKey = Crypto.getPrivateKeyFromString(privateKeyString);
        RSASSASigner rSASSASigner = new RSASSASigner(priKey);
        Date issuedAt = new Date();
        long expiredTime = 600000;
        switch (module) {
            case "tse":
                expiredTime = (isRemember ? tse_expiration_refresh : tse_expiration_access);
                break;
            case "webapp":
                expiredTime = (isRemember ? webapp_expiration_refresh : webapp_expiration_access);
                break;
        }
        Date expirationTime = new Date(issuedAt.getTime() + expiredTime);
        UUID uuid = UUID.randomUUID();
        String jti = uuid.toString();
        JWTClaimsSet.Builder builder = (new JWTClaimsSet.Builder());
        for (String key : claims.keySet()) {
            Object value = claims.get(key);
            builder.claim(key, value);
        }
        JWTClaimsSet claimsSet = builder
                .issuer(issuer)
                .subject(module)
                .issueTime(issuedAt)
                .expirationTime(expirationTime)
                .jwtID(jti)
                .build();
        SignedJWT signedJWT = new SignedJWT((new JWSHeader.Builder(JWSAlgorithm.RS256)).keyID(uuid.toString()).build(), claimsSet);
        signedJWT.sign((JWSSigner) rSASSASigner);
        String token = signedJWT.serialize();
        return token;
    }

    public boolean isValidToken(String token) throws Exception {
        String publicKeyString = fileResourceService.readFileToString("public");
        if (publicKeyString == null) {
            throw new Exception("read file private key in resource error");
        }
        PublicKey publicKey = null;
        try {
            publicKey = Crypto.getPublicKeyFromString(publicKeyString);
        } catch (Exception var1) {
            LOG.error("get public key valid access_token error: " + var1.getMessage());
            return false;
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(token.trim());
            RSASSAVerifier rSASSAVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (!signedJWT.verify((JWSVerifier) rSASSAVerifier)) {
                return false;
            }
            return true;
        } catch (Exception var2) {
            LOG.error("valid acctoken error: " + var2.getMessage());
            return false;
        }
    }

    public String extractClaim(String token, String key) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token.trim());
            return (String) signedJWT.getJWTClaimsSet().getClaim(key);
        } catch (Exception var2) {
            LOG.error("check token is expired error: " + var2.getMessage());
            return null;
        }
    }

    public Map<String, Object> extractClaimAll(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token.trim());
            return signedJWT.getJWTClaimsSet().getClaims();
        } catch (Exception var2) {
            LOG.error("check token is expired error: " + var2.getMessage());
            return null;
        }
    }

    public boolean checkTokenIsExpired(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token.trim());
            if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                return true;
            }
            return false;
        } catch (Exception var2) {
            LOG.error("check token is expired error: " + var2.getMessage());
            return false;
        }
    }
}
