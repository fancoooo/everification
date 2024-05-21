package fpt.signature.sign.domain;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "USER_CMS")
public class UserCms {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;

    @Column(name = "ENABLED", nullable = false, columnDefinition = "BIT(1) default b'1'")
    private boolean enabled;

    @Column(name = "USERNAME", length = 64, nullable = true, columnDefinition = "VARCHAR(64) default b'1'")
    private String username;

    @Column(name = "PASSWORD", length = 64, nullable = true, columnDefinition = "VARCHAR(64)")
    private String password;

    @Column(name = "NAME", length = 64, nullable = false)
    private String name;

    @Column(name = "PROPERTIES", columnDefinition = "TEXT")
    private String properties;

    @Column(name = "CREATED_DT", nullable = false, columnDefinition = "DATETIME(0) default CURRENT_TIMESTAMP(0)")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdDt;

    @Column(name = "MODIFIED_DT", nullable = false, columnDefinition = "DATETIME(0) default CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0)")
    @Temporal(TemporalType.TIMESTAMP)
    private Date modifiedDt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getProperties() {
        return properties;
    }

    public void setProperties(String properties) {
        this.properties = properties;
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
