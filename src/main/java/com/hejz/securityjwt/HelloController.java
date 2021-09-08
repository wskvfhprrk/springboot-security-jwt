package com.hejz.securityjwt;

import com.hejz.securityjwt.dto.LoginDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
    public String hello() {
        return "hello world";
    }

    @PostMapping("login")
    public String login(@RequestBody LoginDto dto, HttpServletRequest request, HttpServletResponse response) throws Exception {
        //todo 验证码登陆验证
        //使用security的usernamePassword验证方式进行验证
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));
        } catch (BadCredentialsException e) {
            //如果认证不能通过报401状态Unauthorized——可以根据业务来重新写
            SimpleUrlAuthenticationFailureHandler s=new SimpleUrlAuthenticationFailureHandler();
            s.onAuthenticationFailure(request,response,new BadCredentialsException("用户名或密码不正确"));
            return null;
        }
        //验证通过后获取jwt的token值
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(dto.getUsername());
        String jwtToken = jwtUtil.generateToken(userDetails);
        return jwtToken;

    }
}
