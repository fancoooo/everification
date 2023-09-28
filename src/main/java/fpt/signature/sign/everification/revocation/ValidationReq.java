package fpt.signature.sign.everification.revocation;

import java.io.Serializable;
import java.util.List;

public class ValidationReq implements Serializable {
    private String entityBillCode;

    private String entityName;

    private int retry;

    private byte[] ocspRequestData;

    private List<String> ocspUris;

    private List<String> crlUris;

    public String getEntityName() {
        return this.entityName;
    }

    public void setEntityName(String entityName) {
        this.entityName = entityName;
    }

    public int getRetry() {
        return this.retry;
    }

    public void setRetry(int retry) {
        this.retry = retry;
    }

    public byte[] getOcspRequestData() {
        return this.ocspRequestData;
    }

    public void setOcspRequestData(byte[] ocspRequestData) {
        this.ocspRequestData = ocspRequestData;
    }

    public String getEntityBillCode() {
        return this.entityBillCode;
    }

    public void setEntityBillCode(String entityBillCode) {
        this.entityBillCode = entityBillCode;
    }

    public List<String> getOcspUris() {
        return this.ocspUris;
    }

    public void setOcspUris(List<String> ocspUris) {
        this.ocspUris = ocspUris;
    }

    public List<String> getCrlUris() {
        return this.crlUris;
    }

    public void setCrlUris(List<String> crlUris) {
        this.crlUris = crlUris;
    }
}

