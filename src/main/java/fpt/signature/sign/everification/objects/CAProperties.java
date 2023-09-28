package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CAProperties extends Attributes {
    private boolean ocspEnabled;

    private boolean crlEnabled;

    private CRL crl;

    private OCSP ocsp;

    private boolean autoEnrollEnabled;

    @JsonProperty("ocspEnabled")
    public boolean isOcspEnabled() {
        return this.ocspEnabled;
    }

    public void setOcspEnabled(boolean ocspEnabled) {
        this.ocspEnabled = ocspEnabled;
    }

    @JsonProperty("crlEnabled")
    public boolean isCrlEnabled() {
        return this.crlEnabled;
    }

    public void setCrlEnabled(boolean crlEnabled) {
        this.crlEnabled = crlEnabled;
    }

    @JsonProperty("crl")
    public CRL getCrl() {
        return this.crl;
    }

    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    @JsonProperty("ocsp")
    public OCSP getOcsp() {
        return this.ocsp;
    }

    public void setOcsp(OCSP ocsp) {
        this.ocsp = ocsp;
    }

    @JsonProperty("autoEnrollEnabled")
    public boolean isAutoEnrollEnabled() {
        return this.autoEnrollEnabled;
    }

    public void setAutoEnrollEnabled(boolean autoEnrollEnabled) {
        this.autoEnrollEnabled = autoEnrollEnabled;
    }
}

