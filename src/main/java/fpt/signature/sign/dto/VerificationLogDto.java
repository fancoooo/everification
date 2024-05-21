package fpt.signature.sign.dto;

import javax.persistence.*;
import java.util.Date;

public class VerificationLogDto {

    private Long id;
    private String relyingPartyName;
    private Long relyingPartyId;
    private String requestData;

    private String responseData;

    private String requestBillcode;

    private String responseBillcode;

    private String responseCode;

    private String functionName;

    private String requestIp;

    private Date createdDt;

    private Date modifiedDt;
    private String timeRequest;
    private String timeResponse;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTimeRequest() {
        return timeRequest;
    }

    public void setTimeRequest(String timeRequest) {
        this.timeRequest = timeRequest;
    }

    public String getTimeResponse() {
        return timeResponse;
    }

    public void setTimeResponse(String timeResponse) {
        this.timeResponse = timeResponse;
    }

    public String getRelyingPartyName() {
        return relyingPartyName;
    }

    public void setRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
    }

    public Long getRelyingPartyId() {
        return relyingPartyId;
    }

    public void setRelyingPartyId(Long relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
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

    public String getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(String responseCode) {
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
