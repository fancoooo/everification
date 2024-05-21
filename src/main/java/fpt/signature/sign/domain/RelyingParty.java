package fpt.signature.sign.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;

@Entity
@Table(name = "RELYING_PARTY")
@Builder
@AllArgsConstructor
public class RelyingParty implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;

    @Column(name = "ENABLED")
    private Boolean enabled;

    @Column(name = "NAME")
    private String name;

    @Column(name = "AUTH_ENABLED")
    private Boolean ssl2Enabled;

    @Column(name = "PROPERTIES")
    private String properties;
    @Lob
    @Column(name = "AUTH_PROPERTIES")
    private String ssl2Properties;
    @Lob
    @Column(name = "IP_ACCESS")
    private String ipAccess;
    @Lob
    @Column(name = "FUNCTION_ACCESS")
    private String functionAccess;
    @Column(name = "REMARK_EN")
    private String descriptionEn;

    @Column(name = "REMARK")
    private String descriptionVn;

    @Column(name = "CREATED_DT")
    private Instant createdDate;

    @Column(name = "MODIFIED_DT")
    private Instant updatedDate;

    public RelyingParty() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getSsl2Enabled() {
        return ssl2Enabled;
    }

    public void setSsl2Enabled(Boolean ssl2Enabled) {
        this.ssl2Enabled = ssl2Enabled;
    }

    public String getProperties() {
        return properties;
    }

    public void setProperties(String properties) {
        this.properties = properties;
    }

    public String getSsl2Properties() {
        return ssl2Properties;
    }

    public void setSsl2Properties(String ssl2Properties) {
        this.ssl2Properties = ssl2Properties;
    }

    public String getIpAccess() {
        return ipAccess;
    }

    public void setIpAccess(String ipAccess) {
        this.ipAccess = ipAccess;
    }

    public String getFunctionAccess() {
        return functionAccess;
    }

    public void setFunctionAccess(String functionAccess) {
        this.functionAccess = functionAccess;
    }

    public String getDescriptionEn() {
        return descriptionEn;
    }

    public void setDescriptionEn(String descriptionEn) {
        this.descriptionEn = descriptionEn;
    }

    public String getDescriptionVn() {
        return descriptionVn;
    }

    public void setDescriptionVn(String descriptionVn) {
        this.descriptionVn = descriptionVn;
    }

    public Instant getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Instant createdDate) {
        this.createdDate = createdDate;
    }

    public Instant getUpdatedDate() {
        return updatedDate;
    }

    public void setUpdatedDate(Instant updatedDate) {
        this.updatedDate = updatedDate;
    }
}
