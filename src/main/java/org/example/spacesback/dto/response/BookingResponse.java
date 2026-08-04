package org.example.spacesback.dto.response;

import lombok.Data;
import java.util.Date;

@Data
public class BookingResponse {
    private Long id;
    private String reference;
    private String spaceId;
    private String spaceName;
    private String plan;
    private Date startAt;
    private Date endAt;
    private Integer reservedUnits;
    private Double unitPrice;
    private Double totalPrice;
    private String status;
    private String paymentMethod;
    private String paymentStatus;
    private Date createdAt;
}
