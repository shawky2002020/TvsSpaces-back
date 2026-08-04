package org.example.spacesback.service;

import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public CustomUserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User u = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return new CustomUserDetails(
                u.getId(),
                u.getEmail(),
                u.getUsername(),
                u.getPassword(),
                u.getType(),
                List.of(new SimpleGrantedAuthority(u.getRole()))
        );
    }

    public CustomUserDetails loadUserById(Long id) throws UsernameNotFoundException {
        User u = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        return new CustomUserDetails(
                u.getId(),
                u.getEmail(),
                u.getUsername(),
                u.getPassword(),
                u.getType(),
                List.of(new SimpleGrantedAuthority(u.getRole()))
        );
    }
}
