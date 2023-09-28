package fpt.signature.sign.database;

import com.fasterxml.jackson.databind.ObjectMapper;
import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;

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
    public boolean insert_bct_tsa_log(String transaction_id, String request_data, String response_data, String response_code, String request_ip, Date time_request, Date time_response, String X_KEY) {
        long startTime = System.nanoTime();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int numOfRetry = this.retryTimes;
        boolean result = false;
        while (numOfRetry > 0) {
            try {
                String str = "{ call BCT_TSA_LOG_INSERT(?,?,?,?,?,?,?,?) }";
                conn = DatabaseConnectionManager.getInstance().openWriteOnlyConnection();
                cals = conn.prepareCall(str);
                cals.setString("_TRANSACTION_ID", transaction_id);
                cals.setString("_REQUEST_DATA", request_data);
                cals.setString("_RESPONSE_DATA", response_data);
                cals.setString("_RESPONSE_CODE", response_code);
                cals.setString("_REQUEST_IP", request_ip);
                cals.setTimestamp("TIME_REQUEST", new Timestamp(time_request.getTime()));
                cals.setTimestamp("_TIME_RESPONSE", new Timestamp(time_response.getTime()));
                cals.setString("_X_KEY", X_KEY);

                cals.execute();
                result = true;
                break;
            } catch (Exception e) {
                numOfRetry--;
                e.printStackTrace();
                LOG.error(e);
            } finally {
                LOG.debug("["+ transaction_id +"] Close connection");
                DatabaseConnectionManager.getInstance().close(conn);
            }
        }
        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        LOG.debug("["+ transaction_id +"]Execution time of insert_bct_tsa_log in milliseconds: " + (timeElapsed / 1000000L));
        return result;
    }

    @Override
    public List<CertificationAuthority> getCertificationAuthorities() {
        long startTime = System.nanoTime();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<CertificationAuthority> certificationAuthorities = new ArrayList<>();
        try {
            String str = "{ call SP_FO_CERTIFICATE_AUTHORITY_LIST() }";
            conn = DatabaseConnectionManager.getInstance().openReadOnlyConnection();
            cals = conn.prepareCall(str);

                LOG.debug("[SQL] " + cals.toString());
            cals.execute();
            rs = cals.getResultSet();
            if (rs != null)
                while (rs.next()) {
                    CertificationAuthority certificationAuthority = new CertificationAuthority();
                    certificationAuthority.setCertificationAuthorityID(rs.getInt("ID"));
                    certificationAuthority.setName(rs.getString("NAME"));
                    certificationAuthority.setUri(rs.getString("URI"));
                    if (rs.getTimestamp("EFFECTIVE_DT") != null)
                        certificationAuthority.setEffectiveDate(new Date(rs.getTimestamp("EFFECTIVE_DT").getTime()));
                    if (rs.getTimestamp("EXPIRATION_DT") != null)
                        certificationAuthority.setExpiredDate(new Date(rs.getTimestamp("EXPIRATION_DT").getTime()));
                    if (Utils.isNullOrEmpty(rs.getString("CERTIFICATE")))
                        continue;
                    certificationAuthority.setPemCertificate(rs.getString("CERTIFICATE"));
                    certificationAuthority.setPemExCertificate(rs.getString("EX_CERTIFICATE"));
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
}
