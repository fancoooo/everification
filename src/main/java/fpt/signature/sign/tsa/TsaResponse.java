package fpt.signature.sign.tsa;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Date;

public class TsaResponse {
    public DatainfoR info;
    public DataContentR content;


    public TsaResponse() {
        content = new DataContentR();
        info = new DatainfoR();
    }

    @JsonIgnore
    public int getResponseCode(){
        return this.info.responseCode;
    }
}
