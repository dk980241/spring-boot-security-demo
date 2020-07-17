package site.yuyanjia.springbootsecuritydemo.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

/**
 * JwtAuthenticationToken
 *
 * @author seer
 * @date 2020/7/17 16:56
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private String token;

    public JwtAuthenticationToken(String token) {
        super(Collections.emptyList());
        this.token = token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }
}
