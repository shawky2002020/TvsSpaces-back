package org.example.spacesback.service;

import lombok.RequiredArgsConstructor;
import org.example.spacesback.model.Booking;
import org.example.spacesback.model.Space;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.BookingRepository;
import org.example.spacesback.repository.SpaceRepository;
import org.example.spacesback.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.SimpleDateFormat;
import java.util.*;

@Service
@RequiredArgsConstructor
public class BookingService {

    private final SpaceRepository spaceRepository;
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;

    public List<Space> getAllSpaces() {
        return spaceRepository.findAll();
    }

    public Space getSpaceById(String id) {
        return spaceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Space not found with id: " + id));
    }

    public double calculatePrice(String spaceId, String plan, String dateStr, String endDateStr, int startTime, int endTime, int quantity) {
        Space space = getSpaceById(spaceId);
        Date start = parseDateTime(dateStr, startTime);
        Date end = parseDateTime(endDateStr != null ? endDateStr : dateStr, endTime);
        return calculatePriceInternal(space, plan, start, end, quantity);
    }

    private double calculatePriceInternal(Space space, String plan, Date start, Date end, int quantity) {
        if (quantity <= 0) return 0.0;
        if ("Hourly".equalsIgnoreCase(plan)) {
            long diffMs = end.getTime() - start.getTime();
            double hours = diffMs / (1000.0 * 60 * 60);
            if (hours <= 0) hours = 1;
            return space.getHourlyPrice() * hours * quantity;
        } else if ("Half-day".equalsIgnoreCase(plan)) {
            return space.getHalfDayPrice() * quantity;
        } else if ("Daily".equalsIgnoreCase(plan)) {
            long diffMs = end.getTime() - start.getTime();
            long days = diffMs / (1000 * 60 * 60 * 24);
            if (days <= 0) days = 1;
            return space.getDayPrice() * days * quantity;
        } else if ("Monthly".equalsIgnoreCase(plan)) {
            return space.getDayPrice() * 20 * quantity;
        }
        return 0.0;
    }

    public boolean checkAvailability(String spaceId, String dateStr, int startTime, int endTime, int requestedUnits) {
        Space space = getSpaceById(spaceId);
        Date start = parseDateTime(dateStr, startTime);
        Date end = parseDateTime(dateStr, endTime);
        return isAvailable(space, start, end, requestedUnits);
    }

    public boolean isAvailable(Space space, Date start, Date end, int requestedUnits) {
        if (requestedUnits <= 0 || requestedUnits > space.getCapacity()) {
            return false;
        }
        List<Booking> overlaps = bookingRepository.findOverlappingActiveBookings(space.getId(), start, end);

        // Check hour-by-hour concurrency
        long startMs = start.getTime();
        long endMs = end.getTime();
        long hourMs = 1000L * 60 * 60;

        for (long time = startMs; time < endMs; time += hourMs) {
            Date timePoint = new Date(time);
            int currentReserved = 0;
            for (Booking b : overlaps) {
                if (b.getStartAt().before(new Date(time + 1)) && b.getEndAt().after(timePoint)) {
                    currentReserved += b.getReservedUnits();
                }
            }
            if (currentReserved + requestedUnits > space.getCapacity()) {
                return false;
            }
        }
        return true;
    }

    public List<String> getUnavailableDates(String spaceId, int year, int month) {
        Space space = getSpaceById(spaceId);
        List<String> unavailables = new ArrayList<>();

        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month - 1);
        cal.set(Calendar.DATE, 1);

        int daysInMonth = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        for (int d = 1; d <= daysInMonth; d++) {
            cal.set(Calendar.DATE, d);

            cal.set(Calendar.HOUR_OF_DAY, 9);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            Date dayStart = cal.getTime();

            cal.set(Calendar.HOUR_OF_DAY, 17);
            Date dayEnd = cal.getTime();

            if (!isAvailable(space, dayStart, dayEnd, 1)) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                unavailables.add(sdf.format(dayStart));
            }
        }
        return unavailables;
    }

    public Map<String, Object> getAvailabilityGrid(String spaceId, String dateStr) {
        Space space = getSpaceById(spaceId);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Date date;
        try {
            date = sdf.parse(dateStr);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid date format: " + dateStr);
        }

        Calendar cal = Calendar.getInstance();
        cal.setTime(date);

        List<Map<String, Object>> slots = new ArrayList<>();
        for (int h = 9; h <= 17; h++) {
            cal.set(Calendar.HOUR_OF_DAY, h);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            Date hourStart = cal.getTime();

            cal.set(Calendar.HOUR_OF_DAY, h + 1);
            Date hourEnd = cal.getTime();

            boolean avail = isAvailable(space, hourStart, hourEnd, 1);
            slots.add(Map.of("hour", h, "available", avail));
        }

        return Map.of("date", dateStr, "slots", slots);
    }

    @Transactional
    public Booking createBooking(Long userId, String spaceId, String plan, String dateStr, String endDateStr, int startTime, int endTime, int quantity, String paymentMethod) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));
        Space space = spaceRepository.findByIdForUpdate(spaceId)
                .orElseThrow(() -> new IllegalArgumentException("Space not found with id: " + spaceId));

        Date startAt = parseDateTime(dateStr, startTime);
        Date endAt = parseDateTime(endDateStr != null ? endDateStr : dateStr, endTime);

        if (startAt.before(new Date())) {
            throw new IllegalArgumentException("Booking cannot be in the past");
        }
        if (endAt.before(startAt) || endAt.equals(startAt)) {
            throw new IllegalArgumentException("Booking end time must be after start time");
        }

        // Transactional Overlap and Capacity validation
        if (!isAvailable(space, startAt, endAt, quantity)) {
            throw new IllegalStateException("Selected space slot does not have sufficient capacity");
        }

        double totalPrice = calculatePriceInternal(space, plan, startAt, endAt, quantity);
        double unitPrice = calculatePriceInternal(space, plan, startAt, endAt, 1);

        Booking booking = new Booking();
        booking.setReference("BK-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        booking.setUser(user);
        booking.setSpace(space);
        booking.setPlan(plan);
        booking.setStartAt(startAt);
        booking.setEndAt(endAt);
        booking.setReservedUnits(quantity);
        booking.setUnitPrice(unitPrice);
        booking.setTotalPrice(totalPrice);
        booking.setStatus("CONFIRMED");
        booking.setPaymentMethod(paymentMethod != null ? paymentMethod : "PAY_AT_VENUE");
        booking.setPaymentStatus("PENDING");
        booking.setCreatedAt(new Date());
        booking.setUpdatedAt(new Date());

        return bookingRepository.save(booking);
    }

    public List<Booking> getBookingsByUserId(Long userId) {
        return bookingRepository.findByUserId(userId);
    }

    @Transactional
    public Booking cancelBooking(Long bookingId, Long userId) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new IllegalArgumentException("Booking not found with id: " + bookingId));

        if (!booking.getUser().getId().equals(userId)) {
            throw new SecurityException("Unauthorized to cancel this booking");
        }

        booking.setStatus("CANCELLED");
        booking.setUpdatedAt(new Date());
        return bookingRepository.save(booking);
    }

    private Date parseDateTime(String dateStr, int hour) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date baseDate = sdf.parse(dateStr);
            Calendar cal = Calendar.getInstance();
            cal.setTime(baseDate);
            cal.set(Calendar.HOUR_OF_DAY, hour);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            cal.set(Calendar.MILLISECOND, 0);
            return cal.getTime();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid date format or hour: " + dateStr + ", hour: " + hour);
        }
    }
}
