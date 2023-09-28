package fpt.signature.sign.database;

import fpt.signature.sign.everification.objects.CertificationAuthority;

import java.util.Date;
import java.util.List;

public interface Database {
    boolean insert_bct_tsa_log(String transaction_id, String reqeust_data, String response_data, String response_code, String request_id, Date time_request, Date time_response, String X_KEY);

    List<CertificationAuthority> getCertificationAuthorities();
}
