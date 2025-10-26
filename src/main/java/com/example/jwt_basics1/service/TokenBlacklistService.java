package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenBlacklistService {

    // ConcurrentHashMap למניעת בעיות Concurrent Access
    private final ConcurrentHashMap<String, TokenInfo> blacklistedTokens = new ConcurrentHashMap<>();
    private final JwtUtil jwtUtil;

    // מידע על הטוקן ברשימה השחורה
    @Data
    @AllArgsConstructor
    private static class TokenInfo {
        private String token;
        private Date expirationDate;
        private String username;
        private String ipAddress;
        private TokenType tokenType;
    }

    public enum TokenType {
        ACCESS_TOKEN, REFRESH_TOKEN
    }

    /**
     * הוספת טוקן לרשימה השחורה
     */
    public void blacklistToken(String token, String username, String ipAddress, TokenType tokenType) {
        try {
            // קבלת תאריך תפוגה מהטוקן
            Date expirationDate = jwtUtil.getExpirationDateFromToken(token);

            TokenInfo tokenInfo = new TokenInfo(token, expirationDate, username, ipAddress, tokenType);
            blacklistedTokens.put(token, tokenInfo);

            log.info("Token blacklisted for user: {} from IP: {} type: {}",
                    username, ipAddress, tokenType);

            // ניקוי אוטומטי של טוקנים שפגו
            cleanExpiredTokens();

        } catch (Exception e) {
            log.error("Error blacklisting token: {}", e.getMessage());
        }
    }

    /**
     * בדיקה אם טוקן קיים ברשימה השחורה
     */
    public boolean isTokenBlacklisted(String token) {
        // ניקוי אוטומטי לפני בדיקה
        cleanExpiredTokens();
        return blacklistedTokens.containsKey(token);
    }

    /**
     * ניקוי אוטומטי של טוקנים שפג תוקפם
     */
    private void cleanExpiredTokens() {
        Date now = new Date();
        blacklistedTokens.entrySet().removeIf(entry ->
                entry.getValue().getExpirationDate().before(now));
    }

    /**
     * הוספת Refresh Token לרשימה השחורה על ידי שם משתמש
     * פתרון לבעיה שה-Refresh Token לא נשלח ב-logout
     */
    public void blacklistRefreshTokenByUsername(String username, String ipAddress) {
        // מחיפת כל ה-Refresh Tokens של המשתמש ברשימה הקיימת
        blacklistedTokens.entrySet().removeIf(entry -> {
            TokenInfo tokenInfo = entry.getValue();
            if (tokenInfo.getUsername().equals(username) &&
                    tokenInfo.getTokenType() == TokenType.REFRESH_TOKEN) {
                log.info("Refresh token invalidated for user: {} from IP: {}", username, ipAddress);
                return true;
            }
            return false;
        });
    }

    /**
     * בדיקת IP עבור Refresh Token
     */
    public boolean validateRefreshTokenIP(String token, String currentIP) {
        TokenInfo tokenInfo = blacklistedTokens.get(token);
        if (tokenInfo != null && tokenInfo.getTokenType() == TokenType.REFRESH_TOKEN) {
            return tokenInfo.getIpAddress().equals(currentIP);
        }
        return true; // אם לא נמצא במידע, מאפשרים (לצורכי תאימות לאחור)
    }

    /**
     * קבלת סטטיסטיקות על הרשימה השחורה
     */
    public Map<String, Object> getBlacklistStats() {
        cleanExpiredTokens();
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalBlacklistedTokens", blacklistedTokens.size());
        stats.put("accessTokens", blacklistedTokens.values().stream()
                .filter(token -> token.getTokenType() == TokenType.ACCESS_TOKEN).count());
        stats.put("refreshTokens", blacklistedTokens.values().stream()
                .filter(token -> token.getTokenType() == TokenType.REFRESH_TOKEN).count());
        return stats;
    }
}
