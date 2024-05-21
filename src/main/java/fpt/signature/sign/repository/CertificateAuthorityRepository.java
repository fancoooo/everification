package fpt.signature.sign.repository;

import fpt.signature.sign.domain.CertificateAuthority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateAuthorityRepository extends JpaRepository<CertificateAuthority, Long> {
}
