package fpt.signature.sign.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;

@Entity
@Table(name = "CERTIFICATE_AUTHORITY")
@Builder
@AllArgsConstructor
public class CertificateAuthority implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;

    @Column(name = "ENABLED")
    private Boolean enabled;

    @Column(name = "NAME")
    private String name;

    @Column(name = "EFFECTIVE_DT")
    private Instant effectiveDate;

    @Column(name = "EXPIRATION_DT")
    private Instant expirationDate;
    @Lob
    @Column(name = "CERTIFICATE")
    private String certificate;
    @Lob
    @Column(name = "PROPERTIES")
    private String properties;

    @Column(name = "REMARK_EN")
    private String descriptionEn;

    @Column(name = "REMARK")
    private String descriptionVn;

    @Column(name = "CREATED_DT")
    private Instant createdDate;

    @Column(name = "MODIFIED_DT")
    private Instant updatedDate;

    public CertificateAuthority() {

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

    public Instant getEffectiveDate() {
        return effectiveDate;
    }

    public void setEffectiveDate(Instant effectiveDate) {
        this.effectiveDate = effectiveDate;
    }

    public Instant getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Instant expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getProperties() {
        return properties;
    }

    public void setProperties(String properties) {
        this.properties = properties;
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