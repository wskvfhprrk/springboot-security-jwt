package com.hejz.securityjwt;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        //todo 把相应路径权限写入authorities中，在拦截时进行权限路径匹配——mothed+路径 ege:@GET/hello
        authorities.add(new SimpleGrantedAuthority("@GET/hello"));
        //从数据库中根据username查询到出用户信息和用户的路径授权信息
        return new User(s, "123456", authorities);
    }
}
