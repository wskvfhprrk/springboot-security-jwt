package com.hejz.securityjwt.filter;

import com.hejz.securityjwt.JwtProperties;
import com.hejz.securityjwt.JwtUtil;
import com.hejz.securityjwt.MyUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

/**
 * jwt认证和路径权限匹配过滤器
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;
    @Autowired
    private JwtUtil jwtUtil;
    private AntPathMatcher antPathMatcher=new AntPathMatcher();
    @Autowired
    private JwtProperties jwtProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //不需要认证通过的路径
        for (String s : jwtProperties.getNoVerifPath()) {
            if(antPathMatcher.match(request.getRequestURI(), s)){
                filterChain.doFilter(request,response);
                return;
            }
        }
        //获取认证权限头部值——Authorization的value
        String authorization = request.getHeader(jwtProperties.getHeaderKey());
        String jwt = null;
        String username = null;
        UserDetails userDetails;
        try {
            //检测是以Bearer 开头——可以配置
            if (authorization != null && authorization.startsWith(jwtProperties.getHeaderPrefix())) {
                jwt = authorization.replace(jwtProperties.getHeaderPrefix(), "");
                username = jwtUtil.extractUsername(jwt);

            }
            //如果username不为空值，但上下文会话的身份验证为空时会被security访问请求拒绝——需要把权限添加进上下文会话管理中
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                userDetails = myUserDetailsService.loadUserByUsername(username);
                //检测一下jwt，如果token有效，再模拟usernamePasswordAuthenticationToken登陆并添加会话到request中
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }else { //如果上下文中存在就从上下文中取出
                userDetails=(UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            }
            //从用户权限中取出路径进行路径匹配（保证用户在UserDetails进行路径授权一致），如果验证不过则报403——AuthenticationServiceException
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            boolean permissionFlag=false;
            for (GrantedAuthority g : authorities) {
                String realPath="@"+request.getMethod()+request.getRequestURI();
                if(antPathMatcher.match(realPath, g.toString())){
                    permissionFlag=true;
                    break;
                }
            }
            if (!permissionFlag) {
                //todo 可以记录到审计日志中
                AccessDeniedHandlerImpl accessDeniedHandler=new AccessDeniedHandlerImpl();
                accessDeniedHandler.handle(request,response,new AuthorizationServiceException("无权权限无法访问"));
                return;
            }
        } catch (ExpiredJwtException e) {
            AccessDeniedHandlerImpl accessDeniedHandler=new AccessDeniedHandlerImpl();
            accessDeniedHandler.handle(request,response,new AuthorizationServiceException("用户名或密码不正确"));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
