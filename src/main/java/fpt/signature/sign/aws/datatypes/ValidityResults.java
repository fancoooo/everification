/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fpt.signature.sign.aws.datatypes;

/**
 * 2021/08/30
 * @author TuoiCM
 */
public class ValidityResults {
    public String signing_form;
    public String signature_id;
    public String algorithm;
    public long signing_time;
    public boolean  success;
    public VerificationDetails verification_details;
    public String subject;
    public String issuer;
    public String thumbprint;
    public String serialnumber;
    public String key_hash;
    public long valid_from;
    public long valid_to;

    public String getSigning_form() {
        return signing_form;
    }

    public void setSigning_form(String signing_form) {
        this.signing_form = signing_form;
    }

    public String getSignature_id() {
        return signature_id;
    }

    public void setSignature_id(String signature_id) {
        this.signature_id = signature_id;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public long getSigning_time() {
        return signing_time;
    }

    public void setSigning_time(long signing_time) {
        this.signing_time = signing_time;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public VerificationDetails getVerification_details() {
        return verification_details;
    }

    public void setVerification_details(VerificationDetails verification_details) {
        this.verification_details = verification_details;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getThumbprint() {
        return thumbprint;
    }

    public void setThumbprint(String thumbprint) {
        this.thumbprint = thumbprint;
    }

    public String getSerialnumber() {
        return serialnumber;
    }

    public void setSerialnumber(String serialnumber) {
        this.serialnumber = serialnumber;
    }

    public String getKey_hash() {
        return key_hash;
    }

    public void setKey_hash(String key_hash) {
        this.key_hash = key_hash;
    }

    public long getValid_from() {
        return valid_from;
    }

    public void setValid_from(long valid_from) {
        this.valid_from = valid_from;
    }

    public long getValid_to() {
        return valid_to;
    }

    public void setValid_to(long valid_to) {
        this.valid_to = valid_to;
    }
}
