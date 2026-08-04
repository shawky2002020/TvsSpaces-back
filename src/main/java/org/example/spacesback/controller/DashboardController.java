package org.example.spacesback.controller;

import lombok.RequiredArgsConstructor;
import org.example.spacesback.model.Booking;
import org.example.spacesback.security.CustomUserDetails;
import org.example.spacesback.service.BookingService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final BookingService bookingService;

    @GetMapping("/stats")
    public ResponseEntity<?> getStats(Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        List<Booking> bookings = bookingService.getBookingsByUserId(userDetails.getId());

        long total = bookings.size();
        long upcoming = 0;
        long completed = 0;
        long cancelled = 0;
        Date now = new Date();

        for (Booking b : bookings) {
            if ("CANCELLED".equals(b.getStatus())) {
                cancelled++;
            } else if ("CONFIRMED".equals(b.getStatus())) {
                if (b.getStartAt().after(now)) {
                    upcoming++;
                } else {
                    completed++;
                }
            }
        }

        // Visits can be mapped to completed + upcoming confirmed bookings
        long visits = completed + upcoming;

        return ResponseEntity.ok(Map.of(
                "totalReservations", total,
                "upcomingReservations", upcoming,
                "completedReservations", completed,
                "cancelledReservations", cancelled,
                "totalVisits", visits,
                "totalPoints", 0
        ));
    }
}
