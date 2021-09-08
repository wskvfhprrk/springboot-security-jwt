package com.hejz.securityjwt.dto;

import lombok.Data;

@Data
public class LoginDto {

    private String imageCode;
    private String username;
    private String password;
}
