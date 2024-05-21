package fpt.signature.sign.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import fpt.signature.sign.object.InternalResponse;
import fpt.signature.sign.utils.Utils;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

public class UsersToken {

    private String[] users = {"vietng:fptca@123", "tuandm26:abc!!!"};
    public InternalResponse Get(AuthRequest req,HttpServletRequest request) throws Exception {

        Boolean OK = false;

        for(int i = 0 ; i < users.length ; i++){
            String[] sp = users[i].split(":");
            if(req.username.equals(sp[0])){
                if(req.password.equals(sp[1])){
                    OK = true;
                }
            }
        }

        if(!OK){
            return new InternalResponse(1001, "Người dùng không tồn tại trong hệ thống", null, null, 0, null);
        }

        String PrivateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEowIBAAKCAQEAgLKTJQqBqfvBPFQBpKNeZfHgh3UyrhKLRZrzA8vBFwNbEvba\n" +
                "9PxhDBAXD9ihjVcqZTvRMjOxDzXLThxysKxLfSFtmjpdrSGWuKPn8KFvjtEMuPxt\n" +
                "i0SD+0grA6cFB2ILt3LUvof90Uv0GjOX4zaTXhcIUV2JYZ6PVFgumxAIbnnH5UxV\n" +
                "uDn2SxDwgsJn4jHJmm+OCAlCU95AqTinxLdZXCbFYysSOVo8qoJbd1oVYSFMF69j\n" +
                "SFCowlXUT9bijhDkbykytAuVWriM68eCgu6gg+l3QWe+9PvJVnNZvr3qhsv63Cwk\n" +
                "GSn2TEWCAYddeOfDDhh3l6Cmb6YQOCipKz4nPQIDAQABAoIBAD9Snh/dmYr/ukZq\n" +
                "txxA3dOfPXCo87S+nxQyd1voxysBlbAxEe70tvNuf0pmtqaKuutwkS/4SyhGua/H\n" +
                "Q482VzZMWldGXI0xN63Fx/uYEwHcTjw+x898eMwM6E01wr2tOkKbF55f3z059/Nk\n" +
                "a1l6ouvqvUb7lPsZP0Cq2tOlAeEJBTM99KykDFJL3qhqOly9jy6MwPxpUIpO2CYj\n" +
                "5e4VpLN5zcBs8bqEmFGslU9LePtfOQiTKWWqzOpHTMD7UBfJGeD/tCYssPwdrLKk\n" +
                "QrLnNpvtgB7QIwBoInjbLu1Ht8ohhgzEDx4nGjTm7r3qOWl53juY+WbwItaJSJV0\n" +
                "sucIAwECgYEA7tpu478lfWH3M/YbV1/whtRHZIXZsgdjAJBmf/ptZ7WIjPr+wkzi\n" +
                "CfDqf3SNjCp3N/zUnV4CfbKbv/9265FFvFdeWFK5MdIRjiSBA78z32dN+n5KP1rt\n" +
                "I2RVAWxy+ArUObZbxVm1uYwGVJLCB/SiN4KV/EVx7lEY5UaR2E5RpN0CgYEAie+8\n" +
                "f8gzslKLXgqrM9RcQQK/Yybu0l6utQe4UkuqaX0X3gszxgtBGFVtkZN9CG/OtKoK\n" +
                "T9cfi8PwlIKctIujTj8wWgIMKtfYo5rTTlPewOVyUMMMt4kTHmtx0SouEpc0M0q6\n" +
                "spj65S8hF3NuaF292sOk/g+H0/bCptFIgMbcteECgYEA1EUV1ZszcymUKv6mL9GY\n" +
                "jgqr4/88iAYeiwrJvSTPBCMF1tzdecof/Fu520m23gGDcCNmxPAeYJ1R46Dii9nQ\n" +
                "UuCGfRIPeeJKLbvtWGodbIZ/e4Wu8H0bUJ/DF//McPoWv698AXiHkv2JRrIidDWJ\n" +
                "0LFiIA+LgBNcf65mwQhhcJUCgYADEqgsYJVmP5iDO9GckfqMKDeDSfbAEQPrXISq\n" +
                "sKzXNMY3WCCLJO0KUbzjJVn/uh3swG0CYlR9lJvjcxVyoDm/IIE/QBRtT+mvm19h\n" +
                "u1SXD4WAbxf1bsRSRSp/8mScXWn4So3mNKpCOM6P6y5mfNAh84HVdxsbib/EX50x\n" +
                "4TxBgQKBgBsomDFEBQjvxNPEjtngHJxfc2Bjaksh19YG7S0EXiexg2IDvbsIOnWl\n" +
                "EZCKURwu8lgyz/qhTGrQ+01hBaLneJm30/qYPWUFa5L3FqlBDhqKdGzYKe+sZIXA\n" +
                "kr9vFtp0RTz4mkrkwocR17ayRDwXsOkHf5F8yaYObVlNo8Ytcjed\n" +
                "-----END RSA PRIVATE KEY-----";

        PrivateKey priKey = Utils.getPrivateKeyFromString(PrivateKeyString);


        RSASSASigner rSASSASigner = new RSASSASigner(priKey);
        Date issuedAt = new Date();
        Date expirationTime = new Date(issuedAt.getTime() + (3600 * 1000));
        UUID uuid = UUID.randomUUID();
        String jti = uuid.toString();
        JWTClaimsSet claimsSet = (new JWTClaimsSet.Builder()).subject(req.username).issuer("https://fptca.vn").claim(req.username, req.password).issueTime(issuedAt).expirationTime(expirationTime).jwtID(jti).build();
        SignedJWT signedJWT = new SignedJWT((new JWSHeader.Builder(JWSAlgorithm.RS256)).keyID("fptca@123").build(), claimsSet);
        signedJWT.sign((JWSSigner)rSASSASigner);
        String accessToken = signedJWT.serialize();

        return new InternalResponse(0, "Thành công", accessToken, "Bearer", 3600, null);

    }

    public InternalResponse veriry(HttpServletRequest request) throws Exception {
        String publicKeyString = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgLKTJQqBqfvBPFQBpKNe\n" +
                "ZfHgh3UyrhKLRZrzA8vBFwNbEvba9PxhDBAXD9ihjVcqZTvRMjOxDzXLThxysKxL\n" +
                "fSFtmjpdrSGWuKPn8KFvjtEMuPxti0SD+0grA6cFB2ILt3LUvof90Uv0GjOX4zaT\n" +
                "XhcIUV2JYZ6PVFgumxAIbnnH5UxVuDn2SxDwgsJn4jHJmm+OCAlCU95AqTinxLdZ\n" +
                "XCbFYysSOVo8qoJbd1oVYSFMF69jSFCowlXUT9bijhDkbykytAuVWriM68eCgu6g\n" +
                "g+l3QWe+9PvJVnNZvr3qhsv63CwkGSn2TEWCAYddeOfDDhh3l6Cmb6YQOCipKz4n\n" +
                "PQIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        PublicKey publicKey = Utils.getPublicKeyFromString(publicKeyString);
        String accessToken = Utils.getRequestHeader(request,"Authorization").substring(7);
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        RSASSAVerifier rSASSAVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        if (!signedJWT.verify((JWSVerifier)rSASSAVerifier)) {
            return new InternalResponse(1002, "access_token is invalid.", null, null, 0, null);
        }

        if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
            return new InternalResponse(1003, "access_token is expried.", null, null, 0, null);
        }

        String subject = signedJWT.getJWTClaimsSet().getSubject();

        return new InternalResponse(0, "Thành công", null, null, 0, null);


    }

}
