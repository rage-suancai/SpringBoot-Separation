package com.bootbackend.NoStatus.tool;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

public class Main {

    public static void main(String[] args) {

        //jwtEncrypt("abcABC.12345");

        // eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoibmIiLCJuYW1lIjoibGJ3IiwiaWQiOjEsImV4cCI6NjE2MzQxODg4MDAsImlhdCI6MTY5ODUxNzM2OX0.gRDxUtN-HemDvu8o6DcNQHTtl7lKggP-tqRNAZdVGMw
        base64Teardown("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiYWRtaW4iLCJleHAiOjE2OTg5OTkxNDQsImlhdCI6MTY5ODczOTk0NCwiYXV0aG9yaXRpZXMiOlsiUk9MRV9hZG1pbiIsIlJPTEVfdXNlciJdfQ.QQK_mwr5C6ud5_tv_PHlFScSvmaFhZW31pkWe__wLRA");

    }

    public static void jwtEncrypt(String jwtkey) {

        Algorithm algorithm = Algorithm.HMAC256(jwtkey);

        String jwtToken = JWT.create()
                .withClaim("id", 1)
                .withClaim("name", "lbw")
                .withClaim("role", "nb")
                .withExpiresAt(new Date(2023, Calendar.FEBRUARY, 11))
                .withIssuedAt(new Date()).sign(algorithm);
        System.out.println(jwtToken);

    }

    public static void base64Teardown(String jwtToken) {

        String[] split = jwtToken.split("\\.");
        for (int i = 0; i < split.length - 1; i++) {
            String s = split[i];
            byte[] decode = Base64.getDecoder().decode(s);
            System.out.println(new String(decode));
        }

    }

}
