package fpt.signature.sign.service.impl;

import fpt.signature.sign.domain.CertificateAuthority;
import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CertificateAuthorityDto;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.ex.CodeException;
import fpt.signature.sign.repository.CertificateAuthorityRepository;
import fpt.signature.sign.service.CertificateAuthorityService;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class CertificateAuthorityServiceImpl implements CertificateAuthorityService {

    private final Logger log = LoggerFactory.getLogger(CertificateAuthorityServiceImpl.class);

    private final CertificateAuthorityRepository certificateAuthorityRepository;

    public CertificateAuthorityServiceImpl(CertificateAuthorityRepository certificateAuthorityRepository) {
        this.certificateAuthorityRepository = certificateAuthorityRepository;
    }

    @Override
    public CMSResponse list(HttpServletRequest request) {
        Date date = new Date();
        String billCode = Utils.generateBillCode("webapp",date);
        UserCms userBO = (UserCms) request.getAttribute("user");
        List<CertificateAuthority> certificateAuthorities = certificateAuthorityRepository.findAll();
        List<CertificateAuthorityDto> certificateAuthorityDTOS = new ArrayList<>();
        for (CertificateAuthority ca : certificateAuthorities) {
            CertificateAuthorityDto certificateAuthorityDTO = new CertificateAuthorityDto();
            certificateAuthorityDTO.setId(ca.getId());
            certificateAuthorityDTO.setName(ca.getName());
            certificateAuthorityDTO.setDescriptionEn(ca.getDescriptionEn());
            certificateAuthorityDTO.setEnabled(ca.getEnabled());
            certificateAuthorityDTO.setEffectiveDate(ca.getEffectiveDate());
            certificateAuthorityDTO.setExpirationDate(ca.getExpirationDate());
            certificateAuthorityDTO.setCertificate(Crypto.convertPemCertificate(ca.getCertificate()));
            certificateAuthorityDTO.setProperties(ca.getProperties());
            certificateAuthorityDTOS.add(certificateAuthorityDTO);

        }
        CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billCode, date);
        cmsResponse.setCertificate_authoritys(certificateAuthorityDTOS);
        return cmsResponse;
    }

    @Override
    public CMSResponse create(CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp", date);
        try {
            UserCms userBO = (UserCms) request.getAttribute("user");
            if (
                    Utils.isNullOrEmpty(dto.getName()) ||
                            Utils.isNullOrEmpty(dto.getDescription_en()) ||
                            Utils.isNullOrEmpty(dto.getDescription_vn()) ||
                            Utils.isNullOrEmpty(dto.getProperties()) ||
                            Utils.isNullOrEmpty(dto.getCertificate())
            ) {
                throw new CodeException(1002);
            }
            X509Certificate x509Certificate = Crypto.getX509Object(dto.getCertificate());
            if (x509Certificate == null) {
                log.error("Parse x509Certificate from pem error");
                throw new CodeException(1002);
            }
            CertificateAuthority certificateAuthority = new CertificateAuthority();
            certificateAuthority.setEnabled(dto.getEnabled());
            certificateAuthority.setName(dto.getName());
            certificateAuthority.setDescriptionEn(dto.getDescription_en());
            certificateAuthority.setDescriptionVn(dto.getDescription_vn());
            certificateAuthority.setCertificate(dto.getCertificate());
            certificateAuthority.setProperties(dto.getProperties());
            certificateAuthority.setCreatedDate(date.toInstant());
            certificateAuthority.setEffectiveDate(x509Certificate.getNotBefore().toInstant());
            certificateAuthority.setExpirationDate(x509Certificate.getNotAfter().toInstant());
            certificateAuthorityRepository.save(certificateAuthority);
            CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
            return cmsResponse;
        } catch (CodeException e) {
            return new CMSResponse(
                    e.getResponsecode(),
                    "ERROR",
                    billcode,
                    date
            );
        }
    }

    @Override
    public CMSResponse edit(Long id, CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp",date);
        try {
            UserCms userBO = (UserCms) request.getAttribute("user");
            if (
                    Utils.isNullOrEmpty(dto.getName()) ||
                            Utils.isNullOrEmpty(dto.getDescription_en()) ||
                            Utils.isNullOrEmpty(dto.getDescription_vn()) ||
                            Utils.isNullOrEmpty(dto.getProperties()) ||
                            Utils.isNullOrEmpty(dto.getCertificate())
            ) {
                throw new CodeException(1002);
            }
            Optional<CertificateAuthority> certificateAuthorityOptional = certificateAuthorityRepository.findById(id);
            if (!certificateAuthorityOptional.isPresent()) {
                log.error("find certificate authority id : {} not found", id);
                throw new CodeException(1003);
            }
            X509Certificate x509Certificate = Crypto.getX509Object(dto.getCertificate());
            if (x509Certificate == null) {
                log.error("Parse x509Certificate from pem error");
                throw new CodeException(1002);
            }
            CertificateAuthority certificateAuthority = certificateAuthorityOptional.get();
            certificateAuthority.setEnabled(dto.getEnabled());
            certificateAuthority.setName(dto.getName());
            certificateAuthority.setDescriptionEn(dto.getDescription_en());
            certificateAuthority.setDescriptionVn(dto.getDescription_vn());
            certificateAuthority.setCertificate(dto.getCertificate());
            certificateAuthority.setProperties(dto.getProperties());
            certificateAuthority.setUpdatedDate(date.toInstant());
            certificateAuthority.setEffectiveDate(x509Certificate.getNotBefore().toInstant());
            certificateAuthority.setExpirationDate(x509Certificate.getNotAfter().toInstant());
            certificateAuthorityRepository.save(certificateAuthority);
            CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
            return cmsResponse;
        } catch (CodeException e) {
            return new CMSResponse(
                    e.getResponsecode(),
                    "ERROR",
                    billcode,
                    date
            );
        }
    }
}
