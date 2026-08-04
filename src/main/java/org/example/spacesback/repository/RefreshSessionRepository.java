package org.example.spacesback.repository;

import org.example.spacesback.model.RefreshSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface RefreshSessionRepository extends JpaRepository<RefreshSession, Long> {
    Optional<RefreshSession> findByEmail(String email);
    void deleteByEmail(String email);
}
