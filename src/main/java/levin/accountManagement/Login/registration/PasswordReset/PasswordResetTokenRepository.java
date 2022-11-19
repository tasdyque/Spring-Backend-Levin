package levin.accountManagement.Login.registration.PasswordReset;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long>{

    Optional<PasswordResetToken> findByToken(String token);

    @Transactional
    @Modifying
    @Query("UPDATE PasswordResetToken p " +
            "SET p.confirmedAt = ?2 " +
            "WHERE p.token = ?1")
    int updateConfirmedAt(String token, LocalDateTime confirmedAt);



}
