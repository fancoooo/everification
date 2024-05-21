package fpt.signature.sign.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fpt.signature.sign.core.KeyStoreManager;
import fpt.signature.sign.domain.RelyingParty;
import fpt.signature.sign.domain.UserCms;
import fpt.signature.sign.dto.CMSResponse;
import fpt.signature.sign.dto.CmsDto;
import fpt.signature.sign.dto.DataFileP12;
import fpt.signature.sign.dto.RelyingPartyDto;
import fpt.signature.sign.ex.CodeException;
import fpt.signature.sign.repository.RelyingPartyRepository;
import fpt.signature.sign.repository.UserCmsRepository;
import fpt.signature.sign.service.AuthenService;
import fpt.signature.sign.service.RelyingPartyService;
import fpt.signature.sign.utils.Crypto;
import fpt.signature.sign.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class RelyingPartyServiceImpl implements RelyingPartyService {
    private final Logger log = LoggerFactory.getLogger(RelyingPartyServiceImpl.class);
    private final RelyingPartyRepository relyingPartyRepository;
    private final ObjectMapper mapper = new ObjectMapper();

    public RelyingPartyServiceImpl(
            RelyingPartyRepository relyingPartyRepository
    ) {
        this.relyingPartyRepository = relyingPartyRepository;
    }

    @Override
    public CMSResponse generateP12(CmsDto dto, HttpServletRequest request) throws Exception {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp" ,date);
        UserCms userBO = (UserCms) request.getAttribute("user");
        String password = Utils.isNullOrEmpty(dto.getPassword()) ? "12345678" : dto.getPassword();
        KeyStoreManager keyStoreManager = new KeyStoreManager();
        KeyPair keyPair = keyStoreManager.generate("RSA", 2048);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String keyName = Utils.isNullOrEmpty(dto.getAlias()) ? String.valueOf(System.currentTimeMillis()) : dto.getAlias();
        byte[] kakBinrary = Crypto.generateKeystore(keyName, publicKey.getEncoded(), privateKey, password);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(String.valueOf(System.currentTimeMillis()).getBytes());
        DataFileP12 dataFileP12 = new DataFileP12();
        dataFileP12.setFileData(DatatypeConverter.printBase64Binary(kakBinrary));
        dataFileP12.setFileName(keyName + "_" + password);
        dataFileP12.setSignature(DatatypeConverter.printBase64Binary(signature.sign()));
        dataFileP12.setPublicKeyPem(DatatypeConverter.printBase64Binary(publicKey.getEncoded()));
        CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
        cmsResponse.setDataP12(dataFileP12);
        return cmsResponse;
    }

    @Override
    public CMSResponse createRelyingParty(CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp", date);
        try {
            UserCms userBO = (UserCms) request.getAttribute("user");
            if (
                    Utils.isNullOrEmpty(dto.getName()) ||
                            Utils.isNullOrEmpty(dto.getDescription_vn()) ||
                            Utils.isNullOrEmpty(dto.getDescription_en()) ||
                            Utils.isNullOrEmpty(dto.getSs2_properties()) ||
                            Utils.isNullOrEmpty(dto.getProperties())
            ) {
                log.error(mapper.writeValueAsString(dto));
                throw new CodeException(1002);
            }
            Optional<RelyingParty> relyingPartyOptional = relyingPartyRepository.findByName(dto.getName());
            if (relyingPartyOptional.isPresent()) {
                throw new CodeException(1036);
            }

            RelyingParty relyingParty = new RelyingParty();
            relyingParty.setName(dto.getName());
            relyingParty.setEnabled(dto.getEnabled());
            relyingParty.setSsl2Enabled(dto.getSsl2_enabled());
            relyingParty.setSsl2Properties(dto.getSs2_properties());
            relyingParty.setDescriptionEn(dto.getDescription_en());
            relyingParty.setDescriptionVn(dto.getDescription_vn());
            relyingParty.setProperties(dto.getProperties());
            relyingParty.setCreatedDate(date.toInstant());
            relyingPartyRepository.save(relyingParty);
            CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
            return cmsResponse;
        } catch (CodeException e) {
            return new CMSResponse(
                    e.getResponsecode(),
                    "ERROR",
                    billcode,
                    date
            );
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CMSResponse editRelyingParty(Long id, CmsDto dto, HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp", date);
        try {
            UserCms userBO = (UserCms) request.getAttribute("user");
            if (
                    Utils.isNullOrEmpty(dto.getName()) ||
                            Utils.isNullOrEmpty(dto.getDescription_vn()) ||
                            Utils.isNullOrEmpty(dto.getDescription_en()) ||
                            Utils.isNullOrEmpty(dto.getSs2_properties()) ||
                            Utils.isNullOrEmpty(dto.getProperties())
            ) {
                throw new CodeException(1002);
            }
            Optional<RelyingParty> optionalRelyingParty = relyingPartyRepository.findById(id);
            if (!optionalRelyingParty.isPresent()) {
                throw new CodeException(1003);
            }
            RelyingParty relyingParty = optionalRelyingParty.get();
            relyingParty.setName(dto.getName());
            relyingParty.setEnabled(dto.getEnabled());
            relyingParty.setSsl2Enabled(dto.getSsl2_enabled());
            relyingParty.setSsl2Properties(dto.getSs2_properties());
            relyingParty.setDescriptionEn(dto.getDescription_en());
            relyingParty.setDescriptionVn(dto.getDescription_vn());
            relyingParty.setProperties(dto.getProperties());
            relyingParty.setUpdatedDate(date.toInstant());
            relyingPartyRepository.save(relyingParty);
            return new CMSResponse(0, "SUCCESS!", billcode, date);
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
    public CMSResponse listOfRelyingParty(HttpServletRequest request) {
        Date date = new Date();
        String billcode = Utils.generateBillCode("webapp",date);
        UserCms userBO = (UserCms) request.getAttribute("user");
        List<RelyingParty> relyingParties = relyingPartyRepository.findAll();
        List<RelyingPartyDto> relyingPartyInfos = new ArrayList<>();
        for (RelyingParty rp : relyingParties) {
            RelyingPartyDto relyingPartyInfo = new RelyingPartyDto();
            relyingPartyInfo.setName(rp.getName());
            relyingPartyInfo.setId(rp.getId());
            relyingPartyInfo.setDescription_en(rp.getDescriptionEn());
            relyingPartyInfo.setProperties(rp.getProperties());
            relyingPartyInfo.setEnabled(rp.getEnabled());
            relyingPartyInfo.setSsl_2_enabled(rp.getSsl2Enabled());
            relyingPartyInfo.setSsl_2_properties(rp.getSsl2Properties());
            relyingPartyInfo.setCreated_date(Date.from(rp.getCreatedDate()));
            relyingPartyInfos.add(relyingPartyInfo);
        }
        CMSResponse cmsResponse = new CMSResponse(0, "SUCCESS!", billcode, date);
        cmsResponse.setRelying_partys(relyingPartyInfos);
        return cmsResponse;
    }
}
