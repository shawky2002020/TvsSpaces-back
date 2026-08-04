package org.example.spacesback.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.mapper.BookingMapper;
import org.example.spacesback.dto.mapper.SpaceMapper;
import org.example.spacesback.dto.response.BookingResponse;
import org.example.spacesback.dto.response.SpaceResponse;
import org.example.spacesback.model.Booking;
import org.example.spacesback.security.CustomUserDetails;
import org.example.spacesback.service.BookingService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
public class BookingController {

    private final BookingService bookingService;

    @GetMapping("/spaces")
    public ResponseEntity<List<SpaceResponse>> getSpaces() {
        return ResponseEntity.ok(bookingService.getAllSpaces().stream()
                .map(SpaceMapper::toSpaceResponse)
                .toList());
    }

    @GetMapping("/spaces/{id}")
    public ResponseEntity<SpaceResponse> getSpaceById(@PathVariable String id) {
        return ResponseEntity.ok(SpaceMapper.toSpaceResponse(bookingService.getSpaceById(id)));
    }

    @GetMapping("/{spaceId}/availability/{date}")
    public ResponseEntity<?> getAvailabilityGrid(
            @PathVariable String spaceId,
            @PathVariable String date
    ) {
        return ResponseEntity.ok(bookingService.getAvailabilityGrid(spaceId, date));
    }

    @GetMapping("/{spaceId}/unavailable-dates/{year}/{month}")
    public ResponseEntity<?> getUnavailableDates(
            @PathVariable String spaceId,
            @PathVariable int year,
            @PathVariable int month
    ) {
        return ResponseEntity.ok(Map.of(
                "dates",
                bookingService.getUnavailableDates(spaceId, year, month)
        ));
    }

    @PostMapping("/availability")
    public ResponseEntity<?> checkAvailability(@Valid @RequestBody AvailabilityRequest req) {
        String effectivePlan = req.getPlan();
        if (effectivePlan == null || effectivePlan.isBlank()) {
            effectivePlan = req.getStartTime() == 9 && req.getEndTime() >= 17
                    ? "Daily"
                    : "Hourly";
        }

        boolean available = bookingService.checkAvailability(
                req.getSpaceId(),
                effectivePlan,
                req.getDate(),
                req.getEndDate(),
                req.getStartTime(),
                req.getEndTime(),
                req.getRequestedUnits()
        );
        return ResponseEntity.ok(Map.of("available", available));
    }

    @PostMapping("/calculate-price")
    public ResponseEntity<?> calculatePrice(@Valid @RequestBody PriceRequest req) {
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
    public ResponseEntity<BookingResponse> createBooking(
            @Valid @RequestBody BookingRequest req,
            Authentication auth
    ) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
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
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(BookingMapper.toBookingResponse(booking));
    }

    @GetMapping("/me")
    public ResponseEntity<List<BookingResponse>> getMyBookings(Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        List<BookingResponse> responses = bookingService.getBookingsByUserId(userDetails.getId())
                .stream()
                .map(BookingMapper::toBookingResponse)
                .toList();
        return ResponseEntity.ok(responses);
    }

    @PatchMapping("/{id}/cancel")
    public ResponseEntity<?> cancelBooking(@PathVariable Long id, Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        bookingService.cancelBooking(id, userDetails.getId());
        return ResponseEntity.ok(Map.of("message", "Booking cancelled successfully"));
    }

    @Data
    public static class AvailabilityRequest {
        @NotBlank
        private String spaceId;
        private String plan;
        @NotBlank
        private String date;
        private String endDate;
        @Min(0)
        @Max(23)
        private int startTime;
        @Min(1)
        @Max(23)
        private int endTime;
        @Min(1)
        private int requestedUnits;
    }

    @Data
    public static class PriceRequest {
        @NotBlank
        private String spaceId;
        @NotBlank
        private String plan;
        @NotBlank
        private String date;
        private String endDate;
        @Min(0)
        @Max(23)
        private int startTime;
        @Min(1)
        @Max(23)
        private int endTime;
        @Min(1)
        private int quantity;
    }

    @Data
    public static class BookingRequest {
        @NotBlank
        private String spaceId;
        @NotBlank
        private String plan;
        @NotBlank
        private String date;
        private String endDate;
        @Min(0)
        @Max(23)
        private int startTime;
        @Min(1)
        @Max(23)
        private int endTime;
        @Min(1)
        private int quantity;
        private String paymentMethod;
    }
}
