package com.uiseong.global.security;

import com.uiseong.domain.user.domain.User;
import com.uiseong.domain.user.repository.UserRepository;
import com.uiseong.global.error.CustomError;
import com.uiseong.global.error.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new CustomException(CustomError.USER_NOT_FOUND));

        return new CustomUserDetails(user);
    }
}
