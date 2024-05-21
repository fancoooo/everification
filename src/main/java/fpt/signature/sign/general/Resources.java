package fpt.signature.sign.general;


import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fpt.signature.sign.domain.CertificateAuthority;
import fpt.signature.sign.domain.ResponseCode;
import fpt.signature.sign.everification.objects.CAProperties;
import fpt.signature.sign.repository.CertificateAuthorityRepository;
import fpt.signature.sign.repository.RelyingPartyRepository;
import fpt.signature.sign.repository.ResponseCodeRepository;
import fpt.signature.sign.security.ApplicationContextProvider;
import fpt.signature.sign.utils.CertificatePolicy;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.database.DatabaseImp;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Configuration
public class Resources {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.general.Resources.class);

    private static volatile HashMap<Long, CertificationAuthority> certificationAuthorities = new HashMap<>();

    private static volatile HashMap<String, CertificationAuthority> certificationAuthoritiesKeyIdentifiers = new HashMap<>();

    private static volatile List<CertificationAuthority> listOfCertificationAuthority = new ArrayList<>();

    private static volatile HashMap<Long, RelyingParty> relyingPartyById = new HashMap<>();

    private static volatile HashMap<String, RelyingParty> relyingPartyByName = new HashMap<>();
    private static volatile HashMap<String, ResponseCode> responseCodeByName = new HashMap<>();

    private static volatile List<RelyingParty> listOfRelyingParty = new ArrayList<>();

    private final CertificateAuthorityRepository certificateAuthorityRepository;
    private final ResponseCodeRepository responseCodeRepository;
    private final RelyingPartyRepository relyingPartyRepository;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public Resources(CertificateAuthorityRepository certificateAuthorityRepository, ResponseCodeRepository responseCodeRepository, RelyingPartyRepository relyingPartyRepository) {
        this.certificateAuthorityRepository = certificateAuthorityRepository;
        this.responseCodeRepository = responseCodeRepository;
        this.relyingPartyRepository = relyingPartyRepository;
    }

    @PostConstruct
    public void init() throws JsonProcessingException {
        DatabaseImp databaseImpl = new DatabaseImp();
        if (certificationAuthorities.isEmpty()) {
            List<CertificateAuthority> listOfCA = certificateAuthorityRepository.findAll();
            for (CertificateAuthority certificationAuthority : listOfCA) {
                CertificationAuthority ca = new CertificationAuthority();
                ca.setCertificationAuthorityID(certificationAuthority.getId());
                ca.setName(certificationAuthority.getName());
                ca.setEffectiveDate(Date.from(certificationAuthority.getEffectiveDate()));
                ca.setExpiredDate(Date.from(certificationAuthority.getExpirationDate()));
                if (Utils.isNullOrEmpty(certificationAuthority.getCertificate()))
                    continue;
                ca.setPemCertificate(certificationAuthority.getCertificate());
                X509Certificate x509Certificate = Crypto.getX509Object(certificationAuthority.getCertificate());
                if (x509Certificate == null) {
                    LOG.error("Cannot get X509 Certificate object of CA " + certificationAuthority.getName());
                    continue;
                }
                ca.setX509Object(x509Certificate);
                ca.setSubjectDn(x509Certificate.getSubjectDN().toString());
                ca.setRemark(certificationAuthority.getDescriptionVn());
                ca.setRemarkEn(certificationAuthority.getDescriptionEn());
                ca.setSubjectKeyIdentifier(Crypto.getSubjectKeyIdentifier(x509Certificate));
                ca.setIssuerKeyIdentifier(Crypto.getIssuerKeyIdentifier(x509Certificate));
                ca.setCommonName(CertificatePolicy.getCommonName(x509Certificate.getSubjectDN().toString()));
                if (Utils.isNullOrEmpty(certificationAuthority.getProperties())) {
                    CAProperties caProperties = (CAProperties)objectMapper.readValue(certificationAuthority.getProperties(), CAProperties.class);
                    ca.setCaProperties(caProperties);
                }
                certificationAuthorities.put(ca.getCertificationAuthorityID(), ca);
                certificationAuthoritiesKeyIdentifiers.put(ca.getSubjectKeyIdentifier(), ca);
                listOfCertificationAuthority.add(ca);
            }
        }

        if(listOfRelyingParty.isEmpty()){
            List<fpt.signature.sign.domain.RelyingParty> listOfRP = relyingPartyRepository.findAll();
            for (fpt.signature.sign.domain.RelyingParty rp : listOfRP) {
                RelyingParty relyingParty = new RelyingParty();
                relyingParty.setId(rp.getId());
                relyingParty.setName(rp.getName());
                boolean authEnabled = rp.getSsl2Enabled();
                relyingParty.setAuthEnabled(authEnabled);
                if (authEnabled) {
                    String authPropertiesJson = rp.getSsl2Properties();
                    AuthPropertiesJSNObject authPropertiesJSNObject = null;
                    if (!Utils.isNullOrEmpty(authPropertiesJson)) {
                        authPropertiesJSNObject = (AuthPropertiesJSNObject)objectMapper.readValue(authPropertiesJson, AuthPropertiesJSNObject.class);
                    } else {
                        authPropertiesJSNObject = new AuthPropertiesJSNObject();
                    }
                    relyingParty.setAuthProperties(authPropertiesJSNObject);

                } else {
                    LOG.info("Warning! Relying Party : " + rp.getName() +" E_VERIFICATION_ENABLED is False");
                }

                String ipList = rp.getIpAccess();
                IPRestrictionList ipRestrictionList = null;
                if (!Utils.isNullOrEmpty(ipList))
                    ipRestrictionList = (IPRestrictionList)objectMapper.readValue(ipList, IPRestrictionList.class);
                relyingParty.setVerificationIPRestriction(ipRestrictionList);

                String funcList = rp.getFunctionAccess();
                FunctionAccessList funcAccessList = null;
                if(!Utils.isNullOrEmpty(funcList)){
                    funcAccessList = (FunctionAccessList) objectMapper.readValue(funcList, FunctionAccessList.class);
                }
                relyingParty.setFunctionAccessList(funcAccessList);

                String properties = rp.getProperties();
                VerificationPropertiesJSNObject everificationProperties = null;
                if(!Utils.isNullOrEmpty(properties)){
                    everificationProperties = (VerificationPropertiesJSNObject) objectMapper.readValue(properties, VerificationPropertiesJSNObject.class);
                }
                relyingParty.setVerificationProperties(everificationProperties);
                relyingPartyById.put(relyingParty.getId(), relyingParty);
                relyingPartyByName.put(rp.getName(), relyingParty);
                listOfRelyingParty.add(relyingParty);
            }
        }

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
        CertificateAuthorityRepository certificateAuthorityRepository = (CertificateAuthorityRepository) ApplicationContextProvider.getApplicationContext().getBean("CertificateAuthorityRepository");
        HashMap<Long, CertificationAuthority> newCertificationAuthorities = new HashMap<>();
        HashMap<String, CertificationAuthority> newCertificationAuthoritiesKeyIdentifiers = new HashMap<>();
        List<CertificationAuthority> newListOfCertificationAuthority = new ArrayList<>();
        List<CertificateAuthority> listOfCA = certificateAuthorityRepository.findAll();
        for (CertificateAuthority certificationAuthority : listOfCA) {
            CertificationAuthority ca = new CertificationAuthority();
            ca.setCertificationAuthorityID(certificationAuthority.getId());
            ca.setName(certificationAuthority.getName());
            ca.setEffectiveDate(Date.from(certificationAuthority.getEffectiveDate()));
            ca.setExpiredDate(Date.from(certificationAuthority.getExpirationDate()));
            if (Utils.isNullOrEmpty(certificationAuthority.getCertificate()))
                continue;
            ca.setPemCertificate(certificationAuthority.getCertificate());
            X509Certificate x509Certificate = Crypto.getX509Object(certificationAuthority.getCertificate());
            if (x509Certificate == null) {
                LOG.error("Cannot get X509 Certificate object of CA " + certificationAuthority.getName());
                continue;
            }
            ca.setX509Object(x509Certificate);
            ca.setSubjectDn(x509Certificate.getSubjectDN().toString());
            ca.setRemark(certificationAuthority.getDescriptionVn());
            ca.setRemarkEn(certificationAuthority.getDescriptionEn());
            ca.setSubjectKeyIdentifier(Crypto.getSubjectKeyIdentifier(x509Certificate));
            ca.setIssuerKeyIdentifier(Crypto.getIssuerKeyIdentifier(x509Certificate));
            ca.setCommonName(CertificatePolicy.getCommonName(x509Certificate.getSubjectDN().toString()));
            newCertificationAuthorities.put(ca.getCertificationAuthorityID(), ca);
            newCertificationAuthoritiesKeyIdentifiers.put(ca.getSubjectKeyIdentifier(), ca);
            newListOfCertificationAuthority.add(ca);
        }
        certificationAuthorities = newCertificationAuthorities;
        certificationAuthoritiesKeyIdentifiers = newCertificationAuthoritiesKeyIdentifiers;
        listOfCertificationAuthority = newListOfCertificationAuthority;
    }

    public void reloadRP() throws JsonProcessingException {
        DatabaseImp databaseImpl = new DatabaseImp();
        HashMap<Long, RelyingParty> newRPByID = new HashMap<>();
        HashMap<String, RelyingParty> newRPByName = new HashMap<>();
        List<RelyingParty> newListOfRP = new ArrayList<>();
        List<fpt.signature.sign.domain.RelyingParty> listOfRP = relyingPartyRepository.findAll();
        for (fpt.signature.sign.domain.RelyingParty rp : listOfRP) {
            RelyingParty relyingParty = new RelyingParty();
            relyingParty.setId(rp.getId());
            relyingParty.setName(rp.getName());
            boolean authEnabled = rp.getSsl2Enabled();
            relyingParty.setAuthEnabled(authEnabled);
            if (authEnabled) {
                String authPropertiesJson = rp.getSsl2Properties();
                AuthPropertiesJSNObject authPropertiesJSNObject = null;
                if (!Utils.isNullOrEmpty(authPropertiesJson)) {
                    authPropertiesJSNObject = (AuthPropertiesJSNObject)objectMapper.readValue(authPropertiesJson, AuthPropertiesJSNObject.class);
                } else {
                    authPropertiesJSNObject = new AuthPropertiesJSNObject();
                }
                relyingParty.setAuthProperties(authPropertiesJSNObject);

            } else {
                LOG.info("Warning! E_VERIFICATION_ENABLED is False");
            }

            String ipList = rp.getIpAccess();
            IPRestrictionList ipRestrictionList = null;
            if (!Utils.isNullOrEmpty(ipList))
                ipRestrictionList = (IPRestrictionList)objectMapper.readValue(ipList, IPRestrictionList.class);
            relyingParty.setVerificationIPRestriction(ipRestrictionList);

            String funcList = rp.getFunctionAccess();
            FunctionAccessList funcAccessList = null;
            if(!Utils.isNullOrEmpty(funcList)){
                funcAccessList = (FunctionAccessList) objectMapper.readValue(funcList, FunctionAccessList.class);
            }
            relyingParty.setFunctionAccessList(funcAccessList);

            String properties = rp.getProperties();
            VerificationPropertiesJSNObject everificationProperties = null;
            if(!Utils.isNullOrEmpty(properties)){
                everificationProperties = (VerificationPropertiesJSNObject) objectMapper.readValue(properties, VerificationPropertiesJSNObject.class);
            }
            relyingParty.setVerificationProperties(everificationProperties);
            newRPByID.put(relyingParty.getId(), relyingParty);
            newRPByName.put(rp.getName(), relyingParty);
            newListOfRP.add(relyingParty);
        }
        relyingPartyById = newRPByID;
        relyingPartyByName = newRPByName;
        listOfRelyingParty = newListOfRP;
    }


    public static HashMap<Long, CertificationAuthority> getCertificationAuthorities() {
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

    public static HashMap<Long, RelyingParty> getRelyingPartyById() {
        return relyingPartyById;
    }

    public static HashMap<String, RelyingParty> getRelyingPartyByName() {
        return relyingPartyByName;
    }

    public static List<RelyingParty> getListOfRelyingParty() {
        return listOfRelyingParty;
    }
}

