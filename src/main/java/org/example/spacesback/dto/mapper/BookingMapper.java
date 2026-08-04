package org.example.spacesback.dto.mapper;

import org.example.spacesback.dto.response.BookingResponse;
import org.example.spacesback.model.Booking;

public class BookingMapper {
    public static BookingResponse toBookingResponse(Booking booking) {
        if (booking == null) return null;
        BookingResponse res = new BookingResponse();
        res.setId(booking.getId());
        res.setReference(booking.getReference());
        res.setSpaceId(booking.getSpace().getId());
        res.setSpaceName(booking.getSpace().getName());
        res.setPlan(booking.getPlan());
        res.setStartAt(booking.getStartAt());
        res.setEndAt(booking.getEndAt());
        res.setReservedUnits(booking.getReservedUnits());
        res.setUnitPrice(booking.getUnitPrice());
        res.setTotalPrice(booking.getTotalPrice());
        res.setStatus(booking.getStatus());
        res.setPaymentMethod(booking.getPaymentMethod());
        res.setPaymentStatus(booking.getPaymentStatus());
        res.setCreatedAt(booking.getCreatedAt());
        return res;
    }
}
