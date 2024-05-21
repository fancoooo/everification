package fpt.signature.sign.general;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import fpt.signature.sign.domain.ResponseCode;
import fpt.signature.sign.repository.ResponseCodeRepository;
import fpt.signature.sign.security.ApplicationContextProvider;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.database.DatabaseImp;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

public class Resources {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.general.Resources.class);

    private static volatile HashMap<Integer, CertificationAuthority> certificationAuthorities = new HashMap<>();

    private static volatile HashMap<String, CertificationAuthority> certificationAuthoritiesKeyIdentifiers = new HashMap<>();

    private static volatile List<CertificationAuthority> listOfCertificationAuthority = new ArrayList<>();

    private static volatile HashMap<Integer, RelyingParty> relyingPartyById = new HashMap<>();

    private static volatile HashMap<String, RelyingParty> relyingPartyByName = new HashMap<>();
    private static volatile HashMap<String, ResponseCode> responseCodeByName = new HashMap<>();

    private static volatile List<RelyingParty> listOfRelyingParty = new ArrayList<>();


    public static synchronized  void init() {
        DatabaseImp databaseImpl = new DatabaseImp();

        if (certificationAuthorities.isEmpty()) {
            List<CertificationAuthority> listOfCA = databaseImpl.getCertificationAuthorities();
            for (CertificationAuthority certificationAuthority : listOfCA) {
                certificationAuthorities.put(certificationAuthority.getCertificationAuthorityID(), certificationAuthority);
                certificationAuthoritiesKeyIdentifiers.put(certificationAuthority.getSubjectKeyIdentifier(), certificationAuthority);
                listOfCertificationAuthority.add(certificationAuthority);
            }
        }

        if(listOfRelyingParty.isEmpty()){
            List<RelyingParty> listOfRP = databaseImpl.getRelyingParties();
            for (RelyingParty rp : listOfRP) {
                relyingPartyById.put(rp.getId(), rp);
                relyingPartyByName.put(rp.getName(), rp);
                listOfRelyingParty.add(rp);
            }
        }

        ResponseCodeRepository responseCodeRepository = (ResponseCodeRepository) ApplicationContextProvider.getApplicationContext().getBean("ResponseCodeRepository");
        if(responseCodeByName.isEmpty()){
            List<ResponseCode> responseCodes = responseCodeRepository.findAll();
            for (ResponseCode responseCode : responseCodes) {
                responseCodeByName.put(responseCode.getName(), responseCode);
            }
        }
        LOG.info("Service is started up and ready to use!");
    }

    public static void reloadCertificationAuthorities() {
        DatabaseImp databaseImpl = new DatabaseImp();
        HashMap<Integer, CertificationAuthority> newCertificationAuthorities = new HashMap<>();
        HashMap<String, CertificationAuthority> newCertificationAuthoritiesKeyIdentifiers = new HashMap<>();
        List<CertificationAuthority> newListOfCertificationAuthority = new ArrayList<>();
        List<CertificationAuthority> listOfCA = databaseImpl.getCertificationAuthorities();
        for (CertificationAuthority certificationAuthority : listOfCA) {
            newCertificationAuthorities.put(certificationAuthority.getCertificationAuthorityID(), certificationAuthority);
            newCertificationAuthoritiesKeyIdentifiers.put(certificationAuthority.getSubjectKeyIdentifier(), certificationAuthority);
            newListOfCertificationAuthority.add(certificationAuthority);
        }
        certificationAuthorities = newCertificationAuthorities;
        certificationAuthoritiesKeyIdentifiers = newCertificationAuthoritiesKeyIdentifiers;
        listOfCertificationAuthority = newListOfCertificationAuthority;
    }

    public static void reloadRP() {
        DatabaseImp databaseImpl = new DatabaseImp();
        HashMap<Integer, RelyingParty> newRPByID = new HashMap<>();
        HashMap<String, RelyingParty> newRPByName = new HashMap<>();
        List<RelyingParty> newListOfRP = new ArrayList<>();
        List<RelyingParty> listOfCA = databaseImpl.getRelyingParties();
        for (RelyingParty rp : listOfCA) {
            newRPByID.put(rp.getId(), rp);
            newRPByName.put(rp.getName(), rp);
            newListOfRP.add(rp);
        }
        relyingPartyById = newRPByID;
        relyingPartyByName = newRPByName;
        listOfRelyingParty = newListOfRP;
    }


    public static HashMap<Integer, CertificationAuthority> getCertificationAuthorities() {
        return certificationAuthorities;
    }

    public static HashMap<String, CertificationAuthority> getCertificationAuthoritiesKeyIdentifiers() {
        return certificationAuthoritiesKeyIdentifiers;
    }

    public static List<CertificationAuthority> getListOfCertificationAuthority() {
        return listOfCertificationAuthority;
    }

    public static HashMap<String, ResponseCode> getResponseCodes() {
        return responseCodeByName;
    }

    public static HashMap<Integer, RelyingParty> getRelyingPartyById() {
        return relyingPartyById;
    }

    public static HashMap<String, RelyingParty> getRelyingPartyByName() {
        return relyingPartyByName;
    }

    public static List<RelyingParty> getListOfRelyingParty() {
        return listOfRelyingParty;
    }
}

