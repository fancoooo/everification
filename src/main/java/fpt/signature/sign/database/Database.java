package fpt.signature.sign.database;

import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.general.RelyingParty;

import java.util.Date;
import java.util.List;

public interface Database {
    List<CertificationAuthority> getCertificationAuthorities();
    List<RelyingParty> getRelyingParties();
    boolean insertVerificationLog(int rp_id, String request_data, String response_data, String request_bill_code, String response_bill_code, String response_code, String function, String request_ip, Date time_request, Date time_response);
}
