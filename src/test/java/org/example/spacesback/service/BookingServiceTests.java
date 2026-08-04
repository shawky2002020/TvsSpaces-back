package org.example.spacesback.service;

import org.example.spacesback.model.Booking;
import org.example.spacesback.model.Space;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.BookingRepository;
import org.example.spacesback.repository.SpaceRepository;
import org.example.spacesback.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class BookingServiceTests {

    @Autowired
    private BookingService bookingService;

    @Autowired
    private SpaceRepository spaceRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BookingRepository bookingRepository;

    private User testUser;
    private Space soloDesk;

    @BeforeEach
    public void setUp() {
        bookingRepository.deleteAll();

        testUser = new User();
        testUser.setUsername("Tester");
        testUser.setEmail(UUID.randomUUID().toString() + "@test.com");
        testUser.setPassword("password");
        testUser.setType("Individual");
        testUser.setCreationDate(new Date());
        testUser.setLastLogin(new Date());
        testUser.setRole("ROLE_USER");
        testUser.setLoginCount(0);
        userRepository.save(testUser);

        // Fetch or save Space 2 (Solo Desk - Capacity 1)
        soloDesk = spaceRepository.findById("2").orElseGet(() -> {
            Space s = new Space();
            s.setId("2");
            s.setType("desk");
            s.setName("Solo Desk");
            s.setSlug("solo-desk-test");
            s.setCapacity(1);
            s.setHourlyPrice(50.0);
            s.setHalfDayPrice(45.0);
            s.setDayPrice(42.0);
            return spaceRepository.save(s);
        });
    }

    @Test
    public void testCreateBookingSuccess() {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 1);
        cal.set(Calendar.HOUR_OF_DAY, 10);
        String dateStr = new java.text.SimpleDateFormat("yyyy-MM-dd").format(cal.getTime());

        Booking b = bookingService.createBooking(
                testUser.getId(),
                soloDesk.getId(),
                "Hourly",
                dateStr,
                dateStr,
                10,
                12,
                1,
                "PAY_AT_VENUE"
        );

        assertNotNull(b);
        assertNotNull(b.getId());
        assertEquals("CONFIRMED", b.getStatus());
        assertEquals(100.0, b.getTotalPrice()); // 2 hours * 50.0
    }

    @Test
    public void testBookingCapacityConflict() {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 2);
        cal.set(Calendar.HOUR_OF_DAY, 10);
        String dateStr = new java.text.SimpleDateFormat("yyyy-MM-dd").format(cal.getTime());

        // First booking succeeds
        bookingService.createBooking(
                testUser.getId(),
                soloDesk.getId(),
                "Hourly",
                dateStr,
                dateStr,
                10,
                12,
                1,
                "PAY_AT_VENUE"
        );

        // Second overlapping booking must fail since capacity is 1
        assertThrows(IllegalStateException.class, () -> {
            bookingService.createBooking(
                    testUser.getId(),
                    soloDesk.getId(),
                    "Hourly",
                    dateStr,
                    dateStr,
                    11,
                    13,
                    1,
                    "PAY_AT_VENUE"
            );
        });
    }

    @Test
    public void testConcurrentBookingsPreventOverbooking() throws InterruptedException {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 3);
        cal.set(Calendar.HOUR_OF_DAY, 14);
        String dateStr = new java.text.SimpleDateFormat("yyyy-MM-dd").format(cal.getTime());

        int threadCount = 4;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    latch.await(); // wait for trigger signal
                    bookingService.createBooking(
                            testUser.getId(),
                            soloDesk.getId(),
                            "Hourly",
                            dateStr,
                            dateStr,
                            14,
                            16,
                            1,
                            "PAY_AT_VENUE"
                    );
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                }
            });
        }

        latch.countDown(); // trigger threads simultaneously
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);

        // Capacity is 1, so only 1 booking should have succeeded
        assertEquals(1, successCount.get());
        assertEquals(threadCount - 1, failureCount.get());
    }
}
