package com.bootbackend.NoStatus.tool.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

public class JwtUtils {

    private static final String key = "abcABC.12345";

    private static final HashSet<String> blackList = new HashSet<>();

    public static String createJwt(UserDetails user) {

        Algorithm algorithm = Algorithm.HMAC256(key); Calendar calender = Calendar.getInstance();
        Date now = calender.getTime(); calender.add(Calendar.SECOND, 3600 * 24 * 3);

        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("name", user.getUsername())
                .withClaim("authorities", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(calender.getTime())
                .withIssuedAt(now).sign(algorithm);

    }

    public static UserDetails resolveJwt(String token) {

        Algorithm algorithm = Algorithm.HMAC256(key); JWTVerifier jwtVerifier = JWT.require(algorithm).build();

        /*try {
            DecodedJWT verify = jwtVerifier.verify(token); Map<String, Claim> claims = verify.getClaims();
            if (new Date().after(claims.get("exp").asDate())) return null;
            else return User
                    .withUsername(claims.get("name").asString())
                    .password("")
                    .authorities(claims.get("authorities").asArray(String.class))
                    .build();
        } catch (JWTVerificationException e) {
            return null;
        }*/

        try {
            DecodedJWT verify = jwtVerifier.verify(token); Map<String, Claim> claims = verify.getClaims();
            if (blackList.contains(verify.getId())) return null;
            if (new Date().after(claims.get("exp").asDate())) return null;
            return User
                    .withUsername(claims.get("name").asString())
                    .password("")
                    .authorities(claims.get("authorities").asArray(String.class))
                    .build();
        } catch (JWTVerificationException e) {
            return null;
        }

    }

    public static boolean invalidate(String token) {

        Algorithm algorithm = Algorithm.HMAC256(key); JWTVerifier jwtVerifier = JWT.require(algorithm).build();

        try {
            DecodedJWT verify = jwtVerifier.verify(token);
            return blackList.add(verify.getId());
        } catch (JWTVerificationException e) {
            return false;
        }

    }

}
