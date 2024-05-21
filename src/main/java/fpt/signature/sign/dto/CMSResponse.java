package fpt.signature.sign.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CMSResponse implements Serializable {
    private int code;
    private String codeDesc;
    @JsonProperty("resBillcode")
    private String response_billcode;
    private Date timestamp;
    private List<String> data;
    @JsonProperty("userInfo")
    private UserCMSDto user_info;
    private List<UserCMSDto> users;
    @JsonProperty("dataP12")
    private DataFileP12 dataP12;
    @JsonProperty("certificateAuthoritys")
    private List<CertificateAuthorityDto> certificate_authoritys;
    @JsonProperty("relyingPartys")
    private List<RelyingPartyDto> relying_partys;
    private List<VerificationLogDto> verification_logs;
    public CMSResponse() {
    }

    public CMSResponse(int code, String codeDesc, String response_billcode, Date timestamp) {
        this.code = code;
        this.codeDesc = codeDesc;
        this.response_billcode = response_billcode;
        this.timestamp = timestamp;
    }
    public CMSResponse(int code, String codeDesc, String response_billcode, Date timestamp, List<String> data) {
        this.code = code;
        this.codeDesc = codeDesc;
        this.response_billcode = response_billcode;
        this.timestamp = timestamp;
        this.data = data;
    }

    public List<VerificationLogDto> getVerification_logs() {
        return verification_logs;
    }

    public void setVerification_logs(List<VerificationLogDto> verification_logs) {
        this.verification_logs = verification_logs;
    }

    public List<CertificateAuthorityDto> getCertificate_authoritys() {
        return certificate_authoritys;
    }

    public void setCertificate_authoritys(List<CertificateAuthorityDto> certificate_authoritys) {
        this.certificate_authoritys = certificate_authoritys;
    }

    public List<RelyingPartyDto> getRelying_partys() {
        return relying_partys;
    }

    public void setRelying_partys(List<RelyingPartyDto> relying_partys) {
        this.relying_partys = relying_partys;
    }

    public DataFileP12 getDataP12() {
        return dataP12;
    }

    public void setDataP12(DataFileP12 dataP12) {
        this.dataP12 = dataP12;
    }

    public List<String> getData() {
        return data;
    }

    public void setData(List<String> data) {
        this.data = data;
    }

    public List<UserCMSDto> getUsers() {
        return users;
    }

    public void setUsers(List<UserCMSDto> users) {
        this.users = users;
    }

    public UserCMSDto getUser_info() {
        return user_info;
    }

    public void setUser_info(UserCMSDto user_info) {
        this.user_info = user_info;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getCodeDesc() {
        return codeDesc;
    }

    public void setCodeDesc(String codeDesc) {
        this.codeDesc = codeDesc;
    }

    public String getResponse_billcode() {
        return response_billcode;
    }

    public void setResponse_billcode(String response_billcode) {
        this.response_billcode = response_billcode;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }
}

