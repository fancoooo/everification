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
public class VerificationDetails {
    public boolean integrity;
    public boolean certpath_validation;
    public boolean trusted_certificate;
    public Revocation revocation;

    public boolean isIntegrity() {
        return integrity;
    }

    public void setIntegrity(boolean integrity) {
        this.integrity = integrity;
    }

    public boolean isCertpath_validation() {
        return certpath_validation;
    }

    public void setCertpath_validation(boolean certpath_validation) {
        this.certpath_validation = certpath_validation;
    }

    public boolean isTrusted_certificate() {
        return trusted_certificate;
    }

    public void setTrusted_certificate(boolean trusted_certificate) {
        this.trusted_certificate = trusted_certificate;
    }

    public Revocation getRevocation() {
        return revocation;
    }

    public void setRevocation(Revocation revocation) {
        this.revocation = revocation;
    }
}
