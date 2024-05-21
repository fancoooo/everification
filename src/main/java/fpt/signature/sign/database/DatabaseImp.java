package fpt.signature.sign.database;

import com.fasterxml.jackson.databind.ObjectMapper;
import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.general.*;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;

import javax.management.BadAttributeValueExpException;
import java.security.cert.X509Certificate;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class DatabaseImp implements Database{

    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.database.DatabaseImp.class);
    private int retryTimes = 1;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<CertificationAuthority> getCertificationAuthorities() {
        long startTime = System.nanoTime();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<CertificationAuthority> certificationAuthorities = new ArrayList<>();
        try {
            String str = "{ call FPT_CERTIFICATE_AUTHORITY_LIST() }";
            conn = DatabaseConnectionManager.getInstance().openReadOnlyConnection();
            cals = conn.prepareCall(str);

                LOG.debug("[SQL] " + cals.toString());
            cals.execute();
            rs = cals.getResultSet();
            if (rs != null)
                while (rs.next()) {
                    CertificationAuthority certificationAuthority = new CertificationAuthority();
                    certificationAuthority.setCertificationAuthorityID(rs.getLong("ID"));
                    certificationAuthority.setName(rs.getString("NAME"));
                    if (rs.getTimestamp("EFFECTIVE_DT") != null)
                        certificationAuthority.setEffectiveDate(new Date(rs.getTimestamp("EFFECTIVE_DT").getTime()));
                    if (rs.getTimestamp("EXPIRATION_DT") != null)
                        certificationAuthority.setExpiredDate(new Date(rs.getTimestamp("EXPIRATION_DT").getTime()));
                    if (Utils.isNullOrEmpty(rs.getString("CERTIFICATE")))
                        continue;
                    certificationAuthority.setPemCertificate(rs.getString("CERTIFICATE"));
                    //certificationAuthority.setPemExCertificate(rs.getString("EX_CERTIFICATE"));
                    X509Certificate x509Certificate = Crypto.getX509Object(rs.getString("CERTIFICATE"));
                    if (x509Certificate == null) {

                            LOG.error("Cannot get X509 Certificate object of CA " + rs.getString("NAME"));
                        continue;
                    }
                    certificationAuthority.setX509Object(x509Certificate);
                    certificationAuthority.setSubjectDn(x509Certificate.getSubjectDN().toString());
                    certificationAuthority.setRemark(rs.getString("REMARK"));
                    certificationAuthority.setRemarkEn(rs.getString("REMARK_EN"));
                    certificationAuthority.setSubjectKeyIdentifier(Crypto.getSubjectKeyIdentifier(x509Certificate));
                    certificationAuthority.setIssuerKeyIdentifier(Crypto.getIssuerKeyIdentifier(x509Certificate));
                    certificationAuthority.setCommonName(CertificatePolicy.getCommonName(x509Certificate.getSubjectDN().toString()));
                    if (rs.getString("PROPERTIES") != null) {
                        CAProperties caProperties = (CAProperties)objectMapper.readValue(rs.getString("PROPERTIES"), CAProperties.class);
                        certificationAuthority.setCaProperties(caProperties);
                    }
                    certificationAuthorities.add(certificationAuthority);
                }
        } catch (Exception e) {
            LOG.error("Error while getting Certification Authority information. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        } finally {
            DatabaseConnectionManager.getInstance().close(conn);
        }
        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        LOG.debug("Execution time of getCertificationAuthorities in milliseconds: " + (timeElapsed / 1000000L));
        return certificationAuthorities;
    }

    @Override
    public List<RelyingParty> getRelyingParties() {
        long startTime = System.nanoTime();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<RelyingParty> relyingParties = new ArrayList<>();
        try {
            String str = "{ call FPT_RELYING_PARTY_LIST() }";
            conn = DatabaseConnectionManager.getInstance().openReadOnlyConnection();
            cals = conn.prepareCall(str);
            LOG.debug("[SQL] " + cals.toString());
            cals.execute();
            rs = cals.getResultSet();
            if (rs != null)
                while (rs.next()) {
                    RelyingParty relyingParty = new RelyingParty();
                    relyingParty.setId((long) rs.getInt("ID"));
                    relyingParty.setName(rs.getString("NAME"));


                    boolean authEnabled = rs.getBoolean("AUTH_ENABLED");
                    relyingParty.setAuthEnabled(authEnabled);
                    if (authEnabled) {
                        String authPropertiesJson = rs.getString("AUTH_PROPERTIES");
                        AuthPropertiesJSNObject authPropertiesJSNObject = null;
                        if (!Utils.isNullOrEmpty(authPropertiesJson)) {
                            authPropertiesJSNObject = (AuthPropertiesJSNObject)objectMapper.readValue(authPropertiesJson, AuthPropertiesJSNObject.class);
                        } else {
                            authPropertiesJSNObject = new AuthPropertiesJSNObject();
                        }
                        relyingParty.setAuthProperties(authPropertiesJSNObject);

                    } else {
                        LOG.info("Warning! E_VERIFICATION_ENABLED is False");
                    }

                    String ipList = rs.getString("IP_ACCESS");
                    IPRestrictionList ipRestrictionList = null;
                    if (!Utils.isNullOrEmpty(ipList))
                        ipRestrictionList = (IPRestrictionList)objectMapper.readValue(ipList, IPRestrictionList.class);
                    relyingParty.setVerificationIPRestriction(ipRestrictionList);

                    String funcList = rs.getString("FUNCTION_ACCESS");
                    FunctionAccessList funcAccessList = null;
                    if(!Utils.isNullOrEmpty(funcList)){
                        funcAccessList = (FunctionAccessList) objectMapper.readValue(funcList, FunctionAccessList.class);
                    }
                    relyingParty.setFunctionAccessList(funcAccessList);

                    String properties = rs.getString("PROPERTIES");
                    VerificationPropertiesJSNObject everificationProperties = null;
                    if(!Utils.isNullOrEmpty(properties)){
                        everificationProperties = (VerificationPropertiesJSNObject) objectMapper.readValue(properties, VerificationPropertiesJSNObject.class);
                    }
                    relyingParty.setVerificationProperties(everificationProperties);

                    relyingParties.add(relyingParty);
                }
        } catch (Exception e) {
            LOG.error("Error while getting Relying Parties. Details: " + Utils.printStackTrace(e));
        } finally {
            DatabaseConnectionManager.getInstance().close(conn);
        }
        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        LOG.debug("Execution time of getRelyingParties in milliseconds: " + (timeElapsed / 1000000L));
        return relyingParties;
    }

    @Override
    public boolean insertVerificationLog(int rp_id, String request_data, String response_data, String request_bill_code, String response_bill_code,
                                         String response_code, String function, String request_ip, Date time_request, Date time_response) {
        long startTime = System.nanoTime();
        request_data = Utils.cutoffBigDataInJson(request_data, Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE);
        response_data = Utils.cutoffBigDataInJson(response_data, Utils.KEY_TOO_LONG, Utils.KEY_SENSITIVE);
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int numOfRetry = this.retryTimes;
        boolean result = false;
        while (numOfRetry > 0) {
            try {
                String str = "{ call FPT_VERIFICATION_LOG_INSERT(?,?,?,?,?,?,?,?,?,?) }";
                conn = DatabaseConnectionManager.getInstance().openWriteOnlyConnection();
                cals = conn.prepareCall(str);
                cals.setString("_REQUEST_DATA", request_data);
                cals.setString("_RESPONSE_DATA", response_data);
                cals.setInt("_RELYING_PARTY_ID", rp_id);
                cals.setString("_REQUEST_BILLCODE", request_bill_code);
                cals.setString("_RESPONSE_BILLCODE", response_bill_code);
                cals.setString("_RESPONSE_CODE", response_code);
                cals.setString("_FUNCTION", function);
                cals.setString("_REQUEST_IP", request_ip);
                cals.setTimestamp("_TIME_REQUEST", new java.sql.Timestamp(time_request.getTime()));
                cals.setTimestamp("_TIME_RESPONSE", new java.sql.Timestamp(time_response.getTime()));
                LOG.debug("[SQL] " + cals.toString());
                cals.execute();
                result = true;
                break;
            } catch (Exception e) {
                LOG.error("Error while insert verification log retry " + numOfRetry +". Details: " + Utils.printStackTrace(e));
                numOfRetry--;
            } finally {
                DatabaseConnectionManager.getInstance().close(conn);
            }
        }
        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        LOG.debug("Execution time of insertVerificationLog in milliseconds: " + (timeElapsed / 1000000L));
        return result;
    }
}
