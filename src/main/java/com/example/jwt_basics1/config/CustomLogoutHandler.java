package com.example.jwt_basics1.config;

import com.example.jwt_basics1.service.TokenBlacklistService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        String authHeader = request.getHeader("Authorization");
        String ipAddress = getClientIpAddress(request);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);

            try {
                // הוספת Access Token לרשימה השחורה
                String username = authentication != null ? authentication.getName() : "unknown";
                tokenBlacklistService.blacklistToken(accessToken, username, ipAddress,
                        TokenBlacklistService.TokenType.ACCESS_TOKEN);

                // טיפול ב-Refresh Token - ביטול על פי שם משתמש
                tokenBlacklistService.blacklistRefreshTokenByUsername(username, ipAddress);

                log.info("User logged out successfully: {} from IP: {}", username, ipAddress);

                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json");
                response.getWriter().write("{\"message\": \"Logout successful\"}");

            } catch (Exception e) {
                log.error("Error during logout: {}", e.getMessage());
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("{\"error\": \"Logout failed\"}");
            }
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"No token provided\"}");
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }

        return request.getRemoteAddr();
    }
}