package fpt.signature.sign.dto.mapper;

import fpt.signature.sign.domain.VerificationLog;
import fpt.signature.sign.dto.VerificationLogDto;
import org.mapstruct.Mapper;

@Mapper
public interface VerificationLogMapper extends EntityMapper<VerificationLogDto, VerificationLog> {}
