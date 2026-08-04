package org.example.spacesback.service;

import lombok.RequiredArgsConstructor;
import org.example.spacesback.model.Booking;
import org.example.spacesback.model.Space;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.BookingRepository;
import org.example.spacesback.repository.SpaceRepository;
import org.example.spacesback.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class BookingService {

    private static final int OPENING_HOUR = 9;
    private static final int CLOSING_HOUR = 18;

    private final SpaceRepository spaceRepository;
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;

    @Value("${app.businessTimeZone:Africa/Cairo}")
    private String businessTimeZone;

    public List<Space> getAllSpaces() {
        return spaceRepository.findAll();
    }

    public Space getSpaceById(String id) {
        return spaceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Space not found with id: " + id));
    }

    public double calculatePrice(
            String spaceId,
            String plan,
            String dateStr,
            String endDateStr,
            int startTime,
            int endTime,
            int quantity
    ) {
        Space space = getSpaceById(spaceId);
        BookingInterval interval = createInterval(plan, dateStr, endDateStr, startTime, endTime);
        validateBookingRequest(space, interval, quantity, false);
        return calculatePriceInternal(space, interval.plan(), interval.start(), interval.end(), quantity);
    }

    private double calculatePriceInternal(Space space, String plan, Date start, Date end, int quantity) {
        if ("Hourly".equals(plan)) {
            double hours = Duration.between(start.toInstant(), end.toInstant()).toMinutes() / 60.0;
            return space.getHourlyPrice() * hours * quantity;
        }
        if ("Half-day".equals(plan)) {
            return space.getHalfDayPrice() * quantity;
        }
        if ("Daily".equals(plan)) {
            LocalDate startDate = toBusinessDate(start);
            LocalDate endDate = toBusinessDate(end);
            long inclusiveDays = ChronoUnit.DAYS.between(startDate, endDate) + 1;
            return space.getDayPrice() * inclusiveDays * quantity;
        }
        if ("Monthly".equals(plan)) {
            return space.getDayPrice() * 20 * quantity;
        }
        throw new IllegalArgumentException("Unsupported booking plan");
    }

    public boolean checkAvailability(
            String spaceId,
            String plan,
            String dateStr,
            String endDateStr,
            int startTime,
            int endTime,
            int requestedUnits
    ) {
        Space space = getSpaceById(spaceId);
        BookingInterval interval = createInterval(plan, dateStr, endDateStr, startTime, endTime);
        validateBookingRequest(space, interval, requestedUnits, false);
        return isAvailable(space, interval.start(), interval.end(), requestedUnits);
    }

    public boolean isAvailable(Space space, Date start, Date end, int requestedUnits) {
        if (requestedUnits <= 0 || requestedUnits > space.getCapacity() || !end.after(start)) {
            return false;
        }

        List<Booking> overlaps = bookingRepository.findOverlappingActiveBookings(space.getId(), start, end);
        long hourMs = 60L * 60L * 1000L;

        for (long time = start.getTime(); time < end.getTime(); time += hourMs) {
            Date slotStart = new Date(time);
            Date slotEnd = new Date(Math.min(time + hourMs, end.getTime()));
            int currentReserved = overlaps.stream()
                    .filter(booking -> booking.getStartAt().before(slotEnd)
                            && booking.getEndAt().after(slotStart))
                    .mapToInt(Booking::getReservedUnits)
                    .sum();

            if (currentReserved + requestedUnits > space.getCapacity()) {
                return false;
            }
        }
        return true;
    }

    public List<String> getUnavailableDates(String spaceId, int year, int month) {
        Space space = getSpaceById(spaceId);
        LocalDate firstDay;
        try {
            firstDay = LocalDate.of(year, month, 1);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("Invalid year or month");
        }

        List<String> unavailableDates = new ArrayList<>();
        for (int day = 1; day <= firstDay.lengthOfMonth(); day++) {
            LocalDate date = firstDay.withDayOfMonth(day);
            Date dayStart = toDate(date, OPENING_HOUR);
            Date dayEnd = toDate(date, CLOSING_HOUR);
            if (!isAvailable(space, dayStart, dayEnd, 1)) {
                unavailableDates.add(date.toString());
            }
        }
        return unavailableDates;
    }

    public Map<String, Object> getAvailabilityGrid(String spaceId, String dateStr) {
        Space space = getSpaceById(spaceId);
        LocalDate date = parseDate(dateStr);
        List<Map<String, Object>> slots = new ArrayList<>();

        for (int hour = OPENING_HOUR; hour < CLOSING_HOUR; hour++) {
            Date hourStart = toDate(date, hour);
            Date hourEnd = toDate(date, hour + 1);
            slots.add(Map.of(
                    "hour", hour,
                    "available", isAvailable(space, hourStart, hourEnd, 1)
            ));
        }

        return Map.of("date", dateStr, "slots", slots);
    }

    @Transactional
    public Booking createBooking(
            Long userId,
            String spaceId,
            String plan,
            String dateStr,
            String endDateStr,
            int startTime,
            int endTime,
            int quantity,
            String paymentMethod
    ) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));
        Space space = spaceRepository.findByIdForUpdate(spaceId)
                .orElseThrow(() -> new IllegalArgumentException("Space not found with id: " + spaceId));

        BookingInterval interval = createInterval(plan, dateStr, endDateStr, startTime, endTime);
        validateBookingRequest(space, interval, quantity, true);

        if (!isAvailable(space, interval.start(), interval.end(), quantity)) {
            throw new IllegalStateException("Selected space slot does not have sufficient capacity");
        }

        double totalPrice = calculatePriceInternal(
                space,
                interval.plan(),
                interval.start(),
                interval.end(),
                quantity
        );
        if (totalPrice <= 0) {
            throw new IllegalArgumentException("Booking price must be greater than zero");
        }

        Booking booking = new Booking();
        booking.setReference("BK-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT));
        booking.setUser(user);
        booking.setSpace(space);
        booking.setPlan(interval.plan());
        booking.setStartAt(interval.start());
        booking.setEndAt(interval.end());
        booking.setReservedUnits(quantity);
        booking.setUnitPrice(totalPrice / quantity);
        booking.setTotalPrice(totalPrice);
        booking.setStatus("CONFIRMED");
        booking.setPaymentMethod(normalizePaymentMethod(paymentMethod));
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
        if ("CANCELLED".equals(booking.getStatus())) {
            return booking;
        }
        if (booking.getStartAt().before(new Date())) {
            throw new IllegalStateException("Started or completed bookings cannot be cancelled");
        }

        booking.setStatus("CANCELLED");
        booking.setUpdatedAt(new Date());
        return bookingRepository.save(booking);
    }

    private void validateBookingRequest(
            Space space,
            BookingInterval interval,
            int quantity,
            boolean rejectPast
    ) {
        if (quantity <= 0 || quantity > space.getCapacity()) {
            throw new IllegalArgumentException("Requested units must be between 1 and the space capacity");
        }
        if (!interval.end().after(interval.start())) {
            throw new IllegalArgumentException("Booking end time must be after start time");
        }
        if (rejectPast && interval.start().before(new Date())) {
            throw new IllegalArgumentException("Booking cannot be in the past");
        }

        ZonedDateTime start = interval.start().toInstant().atZone(zoneId());
        ZonedDateTime end = interval.end().toInstant().atZone(zoneId());
        if (start.toLocalTime().isBefore(LocalTime.of(OPENING_HOUR, 0))
                || start.toLocalTime().isAfter(LocalTime.of(CLOSING_HOUR - 1, 0))
                || end.toLocalTime().isAfter(LocalTime.of(CLOSING_HOUR, 0))) {
            throw new IllegalArgumentException("Bookings must stay within operating hours 09:00-18:00");
        }
        if ("Half-day".equals(interval.plan())
                && Duration.between(interval.start().toInstant(), interval.end().toInstant()).toHours() != 4) {
            throw new IllegalArgumentException("Half-day bookings must reserve exactly four hours");
        }
    }

    private BookingInterval createInterval(
            String plan,
            String dateStr,
            String endDateStr,
            int startTime,
            int endTime
    ) {
        String normalizedPlan = normalizePlan(plan);
        LocalDate startDate = parseDate(dateStr);
        LocalDate endDate = endDateStr == null || endDateStr.isBlank()
                ? startDate
                : parseDate(endDateStr);

        int normalizedStartHour = startTime;
        int normalizedEndHour = endTime;
        if ("Half-day".equals(normalizedPlan)) {
            normalizedStartHour = OPENING_HOUR;
            normalizedEndHour = OPENING_HOUR + 4;
        } else if (!"Hourly".equals(normalizedPlan)) {
            normalizedStartHour = OPENING_HOUR;
            normalizedEndHour = CLOSING_HOUR;
        }

        return new BookingInterval(
                normalizedPlan,
                toDate(startDate, normalizedStartHour),
                toDate(endDate, normalizedEndHour)
        );
    }

    private String normalizePlan(String plan) {
        if (plan == null) throw new IllegalArgumentException("Booking plan is required");
        return switch (plan.trim().toLowerCase(Locale.ROOT)) {
            case "hourly" -> "Hourly";
            case "half-day", "half day" -> "Half-day";
            case "daily" -> "Daily";
            case "monthly" -> "Monthly";
            default -> throw new IllegalArgumentException("Unsupported booking plan: " + plan);
        };
    }

    private String normalizePaymentMethod(String paymentMethod) {
        if (paymentMethod == null || paymentMethod.isBlank()) return "PAY_AT_VENUE";
        if (!"PAY_AT_VENUE".equalsIgnoreCase(paymentMethod.trim())) {
            throw new IllegalArgumentException("Only PAY_AT_VENUE is currently supported");
        }
        return "PAY_AT_VENUE";
    }

    private LocalDate parseDate(String dateStr) {
        try {
            return LocalDate.parse(dateStr);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("Invalid date format: " + dateStr);
        }
    }

    private Date toDate(LocalDate date, int hour) {
        if (hour < 0 || hour > 23) {
            throw new IllegalArgumentException("Invalid booking hour: " + hour);
        }
        return Date.from(ZonedDateTime.of(date, LocalTime.of(hour, 0), zoneId()).toInstant());
    }

    private LocalDate toBusinessDate(Date date) {
        return date.toInstant().atZone(zoneId()).toLocalDate();
    }

    private ZoneId zoneId() {
        return ZoneId.of(businessTimeZone);
    }

    private record BookingInterval(String plan, Date start, Date end) {}
}
