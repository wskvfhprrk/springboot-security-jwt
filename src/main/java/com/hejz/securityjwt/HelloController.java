package com.hejz.securityjwt;

import com.hejz.securityjwt.dto.LoginDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HelloController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private MyUserDetailsService myUserDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("hello")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity hello() {
        return ResponseEntity.ok("hello world");
    }

    @PostMapping("login")
    public ResponseEntity login(@RequestBody LoginDto dto) throws Exception {
        Map resultmap=new HashMap(2);
        //todo 验证码登陆验证
        //使用security的usernamePassword验证方式进行验证
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));
        } catch (BadCredentialsException e) {
            //如果认证不能通过报401状态Unauthorized——可以根据业务来重新写
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);m
            resultmap.put("error","用户名密码不正确");
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body(resultmap);
        }
        //验证通过后获取jwt的token值
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(dto.getUsername());
        String jwtToken = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.refreshToken(userDetails);
        resultmap.put("token",jwtToken);
        resultmap.put("refreshToken",refreshToken);
        return ResponseEntity.ok(resultmap);

    }
}
