package com.hejz.securityjwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@ConfigurationProperties(prefix = "jwt")
@Component
@Data
public class JwtProperties {
    private String headerKey = "Authorization";
    private String headerPrefix = "Bearer ";
    List<String> noVerifPath;
    private Integer expirationTime=3600000;
    private String secretKey="secret";
}
