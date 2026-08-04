package org.example.spacesback.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
public class SpaceResponse {
    private String id;
    private String type;
    private String name;
    private String slug;
    private String description;
    private String imageUrl;
    private List<String> additionalImages;
    private List<AmenityResponse> amenities;
    private PricingResponse pricing;
    private Integer capacity;

    @Data
    @AllArgsConstructor
    public static class AmenityResponse {
        private String name;
        private String icon;
    }

    @Data
    @AllArgsConstructor
    public static class PricingResponse {
        private Double hourly;
        private Double halfDay;
        private Double day;
    }
}
