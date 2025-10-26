package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final CustomUserDetailsService userDetailsService;

    // אחסון מידע על Refresh Tokens (username -> IP mapping)
    private final ConcurrentHashMap<String, String> refreshTokenIPMapping = new ConcurrentHashMap<>();

    /**
     * יצירת Refresh Token חדש
     */
    public String createRefreshToken(String username, String ipAddress) {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            // שמירת מיפוי בין הטוקן לכתובת IP
            refreshTokenIPMapping.put(refreshToken, ipAddress);

            log.info("Refresh token created for user: {} from IP: {}", username, ipAddress);
            return refreshToken;

        } catch (Exception e) {
            log.error("Error creating refresh token for user: {}", username, e);
            throw new RuntimeException("Failed to create refresh token");
        }
    }

    /**
     * רענון טוקן
     */
    public AuthenticationResponse refreshToken(String refreshToken, String currentIP) {
        try {
            // בדיקה אם הטוקן ברשימה השחורה
            if (tokenBlacklistService.isTokenBlacklisted(refreshToken)) {
                throw new RuntimeException("Refresh token is blacklisted");
            }

            // בדיקת תקפות הטוקן
            if (!jwtUtil.validateToken(refreshToken)) {
                throw new RuntimeException("Invalid refresh token");
            }

            String username = jwtUtil.getUsernameFromToken(refreshToken);

            // בדיקת IP
            String storedIP = refreshTokenIPMapping.get(refreshToken);
            if (storedIP != null && !storedIP.equals(currentIP)) {
                log.warn("IP mismatch for refresh token. Stored: {}, Current: {}, User: {}",
                        storedIP, currentIP, username);
                throw new RuntimeException("IP address mismatch");
            }

            // יצירת טוקנים חדשים
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            String newAccessToken = jwtUtil.generateToken(userDetails);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

            // הוספת הטוקן הישן לרשימה השחורה
            tokenBlacklistService.blacklistToken(refreshToken, username, currentIP,
                    TokenBlacklistService.TokenType.REFRESH_TOKEN);

            // עדכון מיפוי IP
            refreshTokenIPMapping.remove(refreshToken);
            refreshTokenIPMapping.put(newRefreshToken, currentIP);

            log.info("Tokens refreshed successfully for user: {} from IP: {}", username, currentIP);

            return AuthenticationResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .username(username)
                    .build();

        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage());
            throw new RuntimeException("Failed to refresh token: " + e.getMessage());
        }
    }
}
