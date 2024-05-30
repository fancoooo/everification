package fpt.signature.sign.repository;

import fpt.signature.sign.domain.CertificateAuthority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CertificateAuthorityRepository extends JpaRepository<CertificateAuthority, Long> {
    List<CertificateAuthority> findByEnabled(Boolean enabled);
}
