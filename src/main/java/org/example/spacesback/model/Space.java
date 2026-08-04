package org.example.spacesback.model;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Data
@Entity
@Table(name = "spaces")
@ToString(exclude = {"images", "amenities"})
public class Space {

    @Id
    private String id;

    @Column(nullable = false)
    private String type;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String slug;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "image_url")
    private String imageUrl;

    @Column(nullable = false)
    private Integer capacity;

    @Column(name = "hourly_price", nullable = false)
    private Double hourlyPrice;

    @Column(name = "half_day_price", nullable = false)
    private Double halfDayPrice;

    @Column(name = "day_price", nullable = false)
    private Double dayPrice;

    @OneToMany(mappedBy = "space", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonManagedReference
    private List<SpaceImage> images = new ArrayList<>();

    @OneToMany(mappedBy = "space", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonManagedReference
    private List<SpaceAmenity> amenities = new ArrayList<>();
}
