package fpt.signature.sign.repository;

import fpt.signature.sign.domain.RelyingParty;
import fpt.signature.sign.domain.UserCms;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserCmsRepository extends JpaRepository<UserCms, Long> {
    UserCms findByUsername(String username);
}
