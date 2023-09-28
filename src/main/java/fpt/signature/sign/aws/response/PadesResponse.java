/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fpt.signature.sign.aws.response;

import fpt.signature.sign.aws.datatypes.ValidityResults;

import java.util.List;

/**
 * 2021/08/30
 * @author TuoiCM
 */
public class PadesResponse {
    public int status;
    public String message;
    public String transaction_id;
    public List<ValidityResults> validity_results;

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getTransaction_id() {
        return transaction_id;
    }

    public void setTransaction_id(String transaction_id) {
        this.transaction_id = transaction_id;
    }

    public List<ValidityResults> getValidity_results() {
        return validity_results;
    }

    public void setValidity_results(List<ValidityResults> validity_results) {
        this.validity_results = validity_results;
    }
}
