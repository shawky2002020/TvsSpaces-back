package org.example.spacesback.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Date;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false)
    private String username;

    @Column(unique=true, nullable=false)
    private String email;

    @Column(nullable=false)
    @Size(min=8)
    private String password;

    @Column(nullable=false)
    private String role = "ROLE_USER"; // e.g. "ROLE_USER"

    @Column (nullable = false)
    private Date lastLogin;

    @Column (nullable = false)
    private Date creationDate;
}
