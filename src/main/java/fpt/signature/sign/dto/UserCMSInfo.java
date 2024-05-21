package fpt.signature.sign.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Date;
import java.util.PrimitiveIterator;

public class UserCMSInfo implements Serializable {
    private Long id;
    @JsonProperty("userName")
    private String username;
    private boolean enabled;
    @JsonProperty("fullName")
    private String full_name;
    @JsonProperty("emailContract")
    private String email;
    @JsonProperty("phoneContract")
    private String phone;
    @JsonProperty("createDate")
    private Date create_date;
    @JsonProperty("relyingParty")
    private String relying_party;
    private Long level;
    private String persionalID;

    public String getPersionalID() {
        return persionalID;
    }

    public void setPersionalID(String persionalID) {
        this.persionalID = persionalID;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getFull_name() {
        return full_name;
    }

    public void setFull_name(String full_name) {
        this.full_name = full_name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public Date getCreate_date() {
        return create_date;
    }

    public void setCreate_date(Date create_date) {
        this.create_date = create_date;
    }

    public String getRelying_party() {
        return relying_party;
    }

    public void setRelying_party(String relying_party) {
        this.relying_party = relying_party;
    }

    public Long getLevel() {
        return level;
    }

    public void setLevel(Long level) {
        this.level = level;
    }
}

