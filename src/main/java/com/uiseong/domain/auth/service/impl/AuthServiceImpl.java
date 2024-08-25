package com.uiseong.domain.auth.service;

import com.uiseong.domain.auth.dto.request.LoginRequest;
import com.uiseong.domain.auth.dto.request.ReissueRequest;
import com.uiseong.domain.auth.dto.request.SignUpRequest;
import com.uiseong.domain.auth.repository.RefreshTokenRepository;
import com.uiseong.domain.user.domain.User;
import com.uiseong.domain.user.domain.UserRole;
import com.uiseong.domain.user.dto.response.UserResponse;
import com.uiseong.domain.user.repository.UserRepository;
import com.uiseong.global.exception.CustomErrorCode;
import com.uiseong.global.exception.CustomException;
import com.uiseong.global.security.jwt.dto.Jwt;
import com.uiseong.global.security.jwt.enums.JwtType;
import com.uiseong.global.security.jwt.provider.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProvider jwtProvider;

    @Transactional
    @Override
    public void signup(SignUpRequest request) {
        String email = request.email();
        String password = request.password();

        if (userRepository.existsByEmail(email)) throw new CustomException(CustomErrorCode.EMAIL_DUPLICATION);

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(UserRole.USER)
                .build();

        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    @Override
    public Jwt login(LoginRequest request) {
        String email = request.email();
        String password = request.password();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(CustomErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new CustomException(CustomErrorCode.WRONG_PASSWORD);

        Jwt token = jwtProvider.generateToken(email, user.getRole());

        refreshTokenRepository.save(email, token.refreshToken());

        return token;
    }

    @Override
    public Jwt reissue(ReissueRequest request) {
        String refreshToken = request.refreshToken();

        if (jwtProvider.getType(refreshToken) != JwtType.REFRESH)
            throw new CustomException(CustomErrorCode.INVALID_TOKEN_TYPE);

        String email = jwtProvider.getSubject(refreshToken);

        if (!refreshTokenRepository.existsByEmail(email))
            throw new CustomException(CustomErrorCode.INVALID_REFRESH_TOKEN);

        if (!refreshTokenRepository.findByEmail(email).equals(refreshToken))
            throw new CustomException(CustomErrorCode.INVALID_REFRESH_TOKEN);


        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(CustomErrorCode.USER_NOT_FOUND));

        Jwt token = jwtProvider.generateToken(email, user.getRole());

        refreshTokenRepository.save(email, token.refreshToken());

        return token;
    }

    @Transactional(readOnly = true)
    @Override
    public UserResponse me() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(CustomErrorCode.USER_NOT_FOUND));

        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole()
        );
    }
}
