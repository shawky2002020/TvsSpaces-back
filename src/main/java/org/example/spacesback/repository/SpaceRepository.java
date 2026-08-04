package org.example.spacesback.repository;

import jakarta.persistence.LockModeType;
import org.example.spacesback.model.Space;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface SpaceRepository extends JpaRepository<Space, String> {
    Optional<Space> findBySlug(String slug);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM Space s WHERE s.id = :id")
    Optional<Space> findByIdForUpdate(@Param("id") String id);
}
