package org.example.spacesback.repository;

import org.example.spacesback.model.Space;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface SpaceRepository extends JpaRepository<Space, String> {
    Optional<Space> findBySlug(String slug);
}
