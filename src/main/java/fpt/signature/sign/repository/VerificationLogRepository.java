package fpt.signature.sign.repository;

import fpt.signature.sign.domain.CertificateAuthority;
import fpt.signature.sign.domain.VerificationLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VerificationLogRepository extends JpaRepository<VerificationLog, Long> {
}
