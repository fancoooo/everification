package fpt.signature.sign.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

public class RelyingPartyDto {
    private Long id;
    private String name;
    @JsonProperty("descriptionEn")
    private String description_en;
    @JsonProperty("createdDate")
    private Date created_date;
    @JsonProperty("createdBy")
    private String created_by;
    @JsonProperty("enabled")
    private Boolean enabled;
    @JsonProperty("ssl2Enabled")
    private Boolean ssl_2_enabled;
    @JsonProperty("ssl2Properties")
    private String ssl_2_properties;
    private String properties;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDescription_en() {
        return description_en;
    }

    public void setDescription_en(String description_en) {
        this.description_en = description_en;
    }

    public Date getCreated_date() {
        return created_date;
    }

    public void setCreated_date(Date created_date) {
        this.created_date = created_date;
    }

    public String getCreated_by() {
        return created_by;
    }

    public void setCreated_by(String created_by) {
        this.created_by = created_by;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getSsl_2_enabled() {
        return ssl_2_enabled;
    }

    public void setSsl_2_enabled(Boolean ssl_2_enabled) {
        this.ssl_2_enabled = ssl_2_enabled;
    }

    public String getSsl_2_properties() {
        return ssl_2_properties;
    }

    public void setSsl_2_properties(String ssl_2_properties) {
        this.ssl_2_properties = ssl_2_properties;
    }

    public String getProperties() {
        return properties;
    }

    public void setProperties(String properties) {
        this.properties = properties;
    }
}
