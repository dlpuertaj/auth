package com.co.dlp.auth.jwt.utils;


import com.co.dlp.auth.model.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${dlp.app.jwtSecret}")
    private String jwtSecret;

    @Value("${dlp.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        log.info("Bearer token: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateTokenFromUsername(User user){
        String username = user.getUsername();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + Long.parseLong(jwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    public String getUsernameFromToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseClaimsJws(token)
                .getPayload()
                .getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser().verifyWith((SecretKey) key())
                    .build()
            .parseClaimsJws(authToken);

            return true;
        } catch (MalformedJwtException e){
            log.error("Invalid JWT token: {}", e.getMessage());
        }catch (ExpiredJwtException e){
            log.error("JWT token expired: {}", e.getMessage());
        }catch (UnsupportedJwtException e){
            log.error("JWT token is unsupported: {}", e.getMessage());
        }catch (IllegalArgumentException e){
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
