package com.example.jwt_basics1.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;


@Component
@Slf4j
public class JwtUtil {

    private final String jwtSecret;
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;
    private final SecretKey secretKey;

    // Constructor injection of properties
    public JwtUtil(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.access-token-expiration:900000}") long accessTokenExpiration,  // Default: 15 minutes
            @Value("${jwt.refresh-token-expiration:604800000}") long refreshTokenExpiration // Default: 7 days
    ) {
        this.jwtSecret = jwtSecret;
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        log.info("JwtUtil initialized with access token expiration: {} ms, refresh token expiration: {} ms",
                accessTokenExpiration, refreshTokenExpiration);
    }

    // ========================= TOKEN GENERATION =========================

    /**
     * Generate Access Token (JWT) for user authentication
     * Contains user details and authorities, short-lived
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        // Add user authorities/roles to claims
        claims.put("authorities", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // Add token type
        claims.put("token_type", "access");

        return createToken(claims, userDetails.getUsername(), accessTokenExpiration);
    }

    /**
     * Generate Refresh Token for token renewal
     * Minimal claims, long-lived
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        // Add minimal claims for refresh token
        claims.put("token_type", "refresh");

        return createToken(claims, userDetails.getUsername(), refreshTokenExpiration);
    }

    /**
     * Generate token with custom claims and expiration
     */
    public String generateTokenWithClaims(String username, Map<String, Object> claims, long expiration) {
        return createToken(claims, username, expiration);
    }

    /**
     * Core method to create JWT token
     */
    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // ========================= TOKEN VALIDATION =========================

    /**
     * Validate token with user details
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate token without user details (for refresh tokens)
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Token expired: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("JWT token compact of handler are invalid: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during token validation: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true; // Consider invalid tokens as expired
        }
    }

    // ========================= TOKEN INFORMATION EXTRACTION =========================

    /**
     * Extract username from token
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extract expiration date from token
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extract issued date from token
     */
    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    /**
     * Extract token type (access/refresh)
     */
    public String getTokenTypeFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("token_type", String.class));
    }

    /**
     * Extract user authorities from token (mainly for access tokens)
     */
    @SuppressWarnings("unchecked")
    public java.util.List<String> getAuthoritiesFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("authorities", java.util.List.class));
    }

    /**
     * Extract specific claim from token
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from token
     */
    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            // Even if token is expired, we might need the claims (e.g., for blacklisting)
            log.debug("Extracting claims from expired token");
            return e.getClaims();
        }
    }

    // ========================= TOKEN TYPE VALIDATION =========================

    /**
     * Check if token is an access token
     */
    public boolean isAccessToken(String token) {
        try {
            String tokenType = getTokenTypeFromToken(token);
            return "access".equals(tokenType);
        } catch (Exception e) {
            log.warn("Error checking token type: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if token is a refresh token
     */
    public boolean isRefreshToken(String token) {
        try {
            String tokenType = getTokenTypeFromToken(token);
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            log.warn("Error checking token type: {}", e.getMessage());
            return false;
        }
    }

    // ========================= UTILITY METHODS =========================

    /**
     * Get remaining time until token expiration (in milliseconds)
     */
    public long getRemainingExpirationTime(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            Date now = new Date();
            return Math.max(0, expiration.getTime() - now.getTime());
        } catch (Exception e) {
            log.warn("Error getting remaining expiration time: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Check if token will expire within specified minutes
     */
    public boolean willExpireWithinMinutes(String token, int minutes) {
        long remainingTime = getRemainingExpirationTime(token);
        long thresholdTime = minutes * 60 * 1000L; // Convert minutes to milliseconds
        return remainingTime <= thresholdTime;
    }

    /**
     * Extract token from Authorization header
     */
    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Create JWT ID (jti) for token uniqueness
     */
    public String generateJwtId() {
        return java.util.UUID.randomUUID().toString();
    }

    // ========================= CONFIGURATION GETTERS =========================

    /**
     * Get access token expiration time
     */
    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    /**
     * Get refresh token expiration time
     */
    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    /**
     * Get JWT secret (for testing purposes only)
     */
    public String getJwtSecret() {
        return jwtSecret;
    }

    // ========================= TOKEN DEBUGGING =========================

    /**
     * Get token information for debugging (without sensitive data)
     */
    public Map<String, Object> getTokenInfo(String token) {
        Map<String, Object> info = new HashMap<>();
        try {
            info.put("username", getUsernameFromToken(token));
            info.put("tokenType", getTokenTypeFromToken(token));
            info.put("issuedAt", getIssuedAtDateFromToken(token));
            info.put("expiresAt", getExpirationDateFromToken(token));
            info.put("isExpired", isTokenExpired(token));
            info.put("remainingTime", getRemainingExpirationTime(token));
            info.put("isValid", validateToken(token));
        } catch (Exception e) {
            info.put("error", e.getMessage());
            info.put("isValid", false);
        }
        return info;
    }

    /**
     * Print token information (for debugging)
     */
    public void printTokenInfo(String token) {
        log.info("Token Info: {}", getTokenInfo(token));
    }
}