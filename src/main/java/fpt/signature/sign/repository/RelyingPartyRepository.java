package fpt.signature.sign.repository;

import fpt.signature.sign.domain.CertificateAuthority;
import fpt.signature.sign.domain.RelyingParty;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface RelyingPartyRepository extends JpaRepository<RelyingParty, Long> {
    Optional<RelyingParty> findByName(String name);
}
