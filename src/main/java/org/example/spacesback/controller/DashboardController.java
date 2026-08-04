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
        Date now = new Date();

        long upcoming = bookings.stream()
                .filter(booking -> "CONFIRMED".equals(booking.getStatus()))
                .filter(booking -> booking.getStartAt().after(now))
                .count();
        long active = bookings.stream()
                .filter(booking -> "CONFIRMED".equals(booking.getStatus()))
                .filter(booking -> !booking.getStartAt().after(now) && booking.getEndAt().after(now))
                .count();
        long completed = bookings.stream()
                .filter(booking -> "CONFIRMED".equals(booking.getStatus()))
                .filter(booking -> !booking.getEndAt().after(now))
                .count();
        long cancelled = bookings.stream()
                .filter(booking -> "CANCELLED".equals(booking.getStatus()))
                .count();

        return ResponseEntity.ok(Map.of(
                "totalReservations", bookings.size(),
                "upcomingReservations", upcoming,
                "activeReservations", active,
                "completedReservations", completed,
                "cancelledReservations", cancelled,
                "totalVisits", completed
        ));
    }
}
