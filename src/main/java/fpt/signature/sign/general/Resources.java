package fpt.signature.sign.general;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;
import fpt.signature.sign.everification.objects.CertificationAuthority;
import fpt.signature.sign.database.DatabaseImp;

public class Resources {
    private static volatile Logger LOG = Logger.getLogger(fpt.signature.sign.general.Resources.class);




    private static volatile HashMap<Integer, CertificationAuthority> certificationAuthorities = new HashMap<>();

    private static volatile HashMap<String, CertificationAuthority> certificationAuthoritiesKeyIdentifiers = new HashMap<>();

    private static volatile List<CertificationAuthority> listOfCertificationAuthority = new ArrayList<>();


    public static String subjectUUID;

    public static synchronized void init() {
        DatabaseImp databaseImpl = new DatabaseImp();

        if (certificationAuthorities.isEmpty()) {
            List<CertificationAuthority> listOfCA = databaseImpl.getCertificationAuthorities();
            for (CertificationAuthority certificationAuthority : listOfCA) {
                certificationAuthorities.put(Integer.valueOf(certificationAuthority.getCertificationAuthorityID()), certificationAuthority);
                certificationAuthoritiesKeyIdentifiers.put(certificationAuthority.getSubjectKeyIdentifier(), certificationAuthority);
                listOfCertificationAuthority.add(certificationAuthority);
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
            newCertificationAuthorities.put(Integer.valueOf(certificationAuthority.getCertificationAuthorityID()), certificationAuthority);
            newCertificationAuthoritiesKeyIdentifiers.put(certificationAuthority.getSubjectKeyIdentifier(), certificationAuthority);
            newListOfCertificationAuthority.add(certificationAuthority);
        }
        certificationAuthorities = newCertificationAuthorities;
        certificationAuthoritiesKeyIdentifiers = newCertificationAuthoritiesKeyIdentifiers;
        listOfCertificationAuthority = newListOfCertificationAuthority;
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

}

