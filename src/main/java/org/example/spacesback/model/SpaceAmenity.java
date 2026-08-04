package org.example.spacesback.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Data;
import lombok.ToString;

@Data
@Entity
@Table(name = "space_amenities")
@ToString(exclude = "space")
public class SpaceAmenity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "space_id", nullable = false)
    @JsonBackReference
    private Space space;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String icon;
}
