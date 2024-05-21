package fpt.signature.sign.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "VERIFICATION_LOG")
@Builder
@AllArgsConstructor
public class VerificationLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "RELYING_PARTY_ID")
    private RelyingParty relyingParty;

    @Column(name = "REQUEST_DATA", columnDefinition = "TEXT")
    private String requestData;

    @Column(name = "RESPONSE_DATA", columnDefinition = "TEXT")
    private String responseData;

    @Column(name = "REQUEST_BILLCODE", length = 64)
    private String requestBillcode;

    @Column(name = "RESPONSE_BILLCODE", length = 64)
    private String responseBillcode;

    @JoinColumn(name = "RESPONSE_CODE_ID")
    @ManyToOne(fetch = FetchType.LAZY)
    private ResponseCode responseCode;

    @Column(name = "FUNCTION_NAME", length = 64)
    private String functionName;

    @Column(name = "REQUEST_IP", length = 128)
    private String requestIp;

    @Column(name = "CREATED_DT", insertable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdDt;

    @Column(name = "MODIFIED_DT", insertable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date modifiedDt;

    @Column(name = "TIME_REQUEST")
    @Temporal(TemporalType.TIMESTAMP)
    private Date timeRequest;

    @Column(name = "TIME_RESPONSE")
    @Temporal(TemporalType.TIMESTAMP)
    private Date timeResponse;

    public VerificationLog() {

    }

    // Constructors, getters, and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Date getTimeRequest() {
        return timeRequest;
    }

    public void setTimeRequest(Date timeRequest) {
        this.timeRequest = timeRequest;
    }

    public Date getTimeResponse() {
        return timeResponse;
    }

    public void setTimeResponse(Date timeResponse) {
        this.timeResponse = timeResponse;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

    public void setRelyingParty(RelyingParty relyingParty) {
        this.relyingParty = relyingParty;
    }

    public String getRequestData() {
        return requestData;
    }

    public void setRequestData(String requestData) {
        this.requestData = requestData;
    }

    public String getResponseData() {
        return responseData;
    }

    public void setResponseData(String responseData) {
        this.responseData = responseData;
    }

    public String getRequestBillcode() {
        return requestBillcode;
    }

    public void setRequestBillcode(String requestBillcode) {
        this.requestBillcode = requestBillcode;
    }

    public String getResponseBillcode() {
        return responseBillcode;
    }

    public void setResponseBillcode(String responseBillcode) {
        this.responseBillcode = responseBillcode;
    }

    public ResponseCode getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(ResponseCode responseCode) {
        this.responseCode = responseCode;
    }

    public String getFunctionName() {
        return functionName;
    }

    public void setFunctionName(String functionName) {
        this.functionName = functionName;
    }

    public String getRequestIp() {
        return requestIp;
    }

    public void setRequestIp(String requestIp) {
        this.requestIp = requestIp;
    }

    public Date getCreatedDt() {
        return createdDt;
    }

    public void setCreatedDt(Date createdDt) {
        this.createdDt = createdDt;
    }

    public Date getModifiedDt() {
        return modifiedDt;
    }

    public void setModifiedDt(Date modifiedDt) {
        this.modifiedDt = modifiedDt;
    }
}
