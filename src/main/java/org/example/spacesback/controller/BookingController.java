package org.example.spacesback.controller;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.mapper.BookingMapper;
import org.example.spacesback.dto.response.BookingResponse;
import org.example.spacesback.model.Booking;
import org.example.spacesback.model.Space;
import org.example.spacesback.security.CustomUserDetails;
import org.example.spacesback.service.BookingService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
public class BookingController {

    private final BookingService bookingService;

    @GetMapping("/spaces")
    public ResponseEntity<List<Space>> getSpaces() {
        return ResponseEntity.ok(bookingService.getAllSpaces());
    }

    @GetMapping("/spaces/{id}")
    public ResponseEntity<Space> getSpaceById(@PathVariable String id) {
        return ResponseEntity.ok(bookingService.getSpaceById(id));
    }

    @GetMapping("/{spaceId}/availability/{date}")
    public ResponseEntity<?> getAvailabilityGrid(@PathVariable String spaceId, @PathVariable String date) {
        return ResponseEntity.ok(bookingService.getAvailabilityGrid(spaceId, date));
    }

    @GetMapping("/{spaceId}/unavailable-dates/{year}/{month}")
    public ResponseEntity<?> getUnavailableDates(@PathVariable String spaceId, @PathVariable int year, @PathVariable int month) {
        List<String> dates = bookingService.getUnavailableDates(spaceId, year, month);
        return ResponseEntity.ok(Map.of("dates", dates));
    }

    @PostMapping("/availability")
    public ResponseEntity<?> checkAvailability(@RequestBody AvailabilityRequest req) {
        boolean available = bookingService.checkAvailability(
                req.getSpaceId(),
                req.getDate(),
                req.getStartTime(),
                req.getEndTime(),
                req.getRequestedUnits()
        );
        return ResponseEntity.ok(Map.of("available", available));
    }

    @PostMapping("/calculate-price")
    public ResponseEntity<?> calculatePrice(@RequestBody PriceRequest req) {
        double price = bookingService.calculatePrice(
                req.getSpaceId(),
                req.getPlan(),
                req.getDate(),
                req.getEndDate(),
                req.getStartTime(),
                req.getEndTime(),
                req.getQuantity()
        );
        return ResponseEntity.ok(Map.of("price", price));
    }

    @PostMapping
    public ResponseEntity<?> createBooking(@RequestBody BookingRequest req, Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        try {
            Booking booking = bookingService.createBooking(
                    userDetails.getId(),
                    req.getSpaceId(),
                    req.getPlan(),
                    req.getDate(),
                    req.getEndDate(),
                    req.getStartTime(),
                    req.getEndTime(),
                    req.getQuantity(),
                    req.getPaymentMethod()
            );
            return ResponseEntity.status(HttpStatus.CREATED).body(BookingMapper.toBookingResponse(booking));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<List<BookingResponse>> getMyBookings(Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        List<BookingResponse> responses = bookingService.getBookingsByUserId(userDetails.getId())
                .stream()
                .map(BookingMapper::toBookingResponse)
                .collect(Collectors.toList());
        return ResponseEntity.ok(responses);
    }

    @PatchMapping("/{id}/cancel")
    public ResponseEntity<?> cancelBooking(@PathVariable Long id, Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        try {
            bookingService.cancelBooking(id, userDetails.getId());
            return ResponseEntity.ok(Map.of("message", "Booking cancelled successfully"));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("message", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @Data
    public static class AvailabilityRequest {
        private String spaceId;
        private String date;
        private int startTime;
        private int endTime;
        private int requestedUnits;
    }

    @Data
    public static class PriceRequest {
        private String spaceId;
        private String plan;
        private String date;
        private String endDate;
        private int startTime;
        private int endTime;
        private int quantity;
    }

    @Data
    public static class BookingRequest {
        private String spaceId;
        private String plan;
        private String date;
        private String endDate;
        private int startTime;
        private int endTime;
        private int quantity;
        private String paymentMethod;
    }
}
