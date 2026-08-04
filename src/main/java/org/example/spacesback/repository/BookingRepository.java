package org.example.spacesback.repository;

import org.example.spacesback.model.Booking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface BookingRepository extends JpaRepository<Booking, Long> {

    List<Booking> findByUserId(Long userId);

    @Query("SELECT b FROM Booking b WHERE b.space.id = :spaceId AND b.status = 'CONFIRMED' AND b.startAt < :endAt AND b.endAt > :startAt")
    List<Booking> findOverlappingActiveBookings(
            @Param("spaceId") String spaceId,
            @Param("startAt") Date startAt,
            @Param("endAt") Date endAt
    );

    @Query("SELECT b FROM Booking b WHERE b.space.id = :spaceId AND b.status = 'CONFIRMED' AND b.startAt >= :startOfDay AND b.startAt < :endOfDay")
    List<Booking> findBookingsForDate(
            @Param("spaceId") String spaceId,
            @Param("startOfDay") Date startOfDay,
            @Param("endOfDay") Date endOfDay
    );
}
