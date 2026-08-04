package org.example.spacesback.dto.mapper;

import org.example.spacesback.dto.response.SpaceResponse;
import org.example.spacesback.model.Space;

public final class SpaceMapper {

    private SpaceMapper() {}

    public static SpaceResponse toSpaceResponse(Space space) {
        SpaceResponse response = new SpaceResponse();
        response.setId(space.getId());
        response.setType(space.getType());
        response.setName(space.getName());
        response.setSlug(space.getSlug());
        response.setDescription(space.getDescription());
        response.setImageUrl(space.getImageUrl());
        response.setCapacity(space.getCapacity());
        response.setAdditionalImages(space.getImages().stream()
                .map(image -> image.getImageUrl())
                .toList());
        response.setAmenities(space.getAmenities().stream()
                .map(amenity -> new SpaceResponse.AmenityResponse(
                        amenity.getName(),
                        amenity.getIcon()
                ))
                .toList());
        response.setPricing(new SpaceResponse.PricingResponse(
                space.getHourlyPrice(),
                space.getHalfDayPrice(),
                space.getDayPrice()
        ));
        return response;
    }
}
