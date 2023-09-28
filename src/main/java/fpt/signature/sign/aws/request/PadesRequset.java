/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fpt.signature.sign.aws.request;

/**
 * 2021/08/30
 * @author TuoiCM
 */
public class PadesRequset {
    private String lang;
    private boolean signer_information;
    private boolean certificates_information;
    private String document;

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public boolean isSigner_information() {
        return signer_information;
    }

    public void setSigner_information(boolean signer_information) {
        this.signer_information = signer_information;
    }

    public boolean isCertificates_information() {
        return certificates_information;
    }

    public void setCertificates_information(boolean certificates_information) {
        this.certificates_information = certificates_information;
    }

    public String getDocument() {
        return document;
    }

    public void setDocument(String document) {
        this.document = document;
    }
}
