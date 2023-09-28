/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fpt.signature.sign.aws.datatypes;

import fpt.signature.sign.aws.response.PadesResponse;
import fpt.signature.sign.aws.response.TokenResponse;

/**
 * 2021/08/30
 * @author TuoiCM
 */
public class PrintResponse {
    //Pritn Response /v1/e-verification/oidc/token {get acess_token}
    public static void printRespOdicToken(TokenResponse tokenResponse) {
        if(tokenResponse.status != 0) {
            System.out.println("\t\t\t==================ERROR=================");
            System.out.println("stauts: " + tokenResponse.status);
            System.out.println("message: " + tokenResponse.message);
        } else {
            System.out.println("\t\t\t==================RESPONSE /v1/e-verification/oidc/token=================");
            System.out.println("status: " + tokenResponse.status);
            System.out.println("message: " + tokenResponse.message);
            System.out.println("transaction_id: " + tokenResponse.transaction_id);
            System.out.println("access_token: " + tokenResponse.access_token);
            System.out.println("token_type: " + tokenResponse.token_type);
            System.out.println("expires_in: " + tokenResponse.expires_in);
        }
    }
    // Print Response /v1/e-verification/pades
    public static void printRespPades(PadesResponse padesResponse) {
        if(padesResponse.status != 0) {
            System.out.println("\t\t\t==================ERROR=================");
            System.out.println("stauts: " + padesResponse.status);
            System.out.println("message: " + padesResponse.message);
        } else {
            System.out.println("\t\t\t==================RESPONSE /v1/e-verification/pades=================");
            System.out.println("stauts: " + padesResponse.status);
            System.out.println("message: " + padesResponse.message);
            System.out.println("transaction_id: " + padesResponse.transaction_id);
            System.out.println("validity_results: ");
            padesResponse.validity_results.forEach(validity_result -> {
                System.out.println("\tsigning_form: " + validity_result.signing_form);
                System.out.println("\tsignature_id: " + validity_result.signature_id);
                System.out.println("\talgorithm: " + validity_result.algorithm);
                System.out.println("\tsigning_time: " + validity_result.signing_time);
                System.out.println("\ttsuccess: " + validity_result.success);
                System.out.println("\tverification_details: ");
                System.out.println("\t\tintegrity: " + validity_result.verification_details.integrity);
                System.out.println("\t\tcertpath_validation: " + validity_result.verification_details.certpath_validation);
                System.out.println("\t\ttrusted_certificate: " + validity_result.verification_details.trusted_certificate);
                System.out.println("\t\trevocation: ");
                System.out.println("\t\t\tsuccess: " + validity_result.verification_details.revocation.success);
                System.out.println("\t\t\tdescription: " + validity_result.verification_details.revocation.description);
                //System.out.println("\t\t\tstatus: " + validity_result.verification_details.revocation.status);
                //System.out.println("\t\t\tprotocol: " + validity_result.verification_details.revocation.protocol);
                System.out.println("\tsubject: " + validity_result.subject);
                System.out.println("\tissuer: " + validity_result.issuer);
                System.out.println("\tthumbprint: " + validity_result.thumbprint);
                System.out.println("\tserialnumber: " + validity_result.serialnumber);
                System.out.println("\tkey_hash: " + validity_result.key_hash);
                System.out.println("\tvalid_from: " + validity_result.valid_from);
                System.out.println("\tvalid_to: " + validity_result.valid_to);
            });
        }
    }
}
