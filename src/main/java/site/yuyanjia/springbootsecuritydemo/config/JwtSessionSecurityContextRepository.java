package site.yuyanjia.springbootsecuritydemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * JwtSessionSecurityContextRepository
 *
 * @author seer
 * @date 2020/7/17 16:10
 */

public class JwtSessionSecurityContextRepository implements SecurityContextRepository {
    private static final Logger log = LoggerFactory.getLogger(JwtSessionSecurityContextRepository.class);

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        String authToken = request.getHeader(JwtUtil.HEADER);
        if (!JwtUtil.isValid(authToken)) {
            if (log.isDebugEnabled()) {
                log.debug("jwt 无效");
            }
            return null;
        }
        String username = JwtUtil.getUserName(authToken);
        if (log.isDebugEnabled()) {
            log.debug("jwt username {}", username);
        }
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(username);
        securityContext.setAuthentication(authenticationToken);
        return securityContext;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

    }

    /**
     * Allows the repository to be queried as to whether it contains a security context
     * for the current request.
     *
     * @param request the current request
     * @return true if a context is found for the request, false otherwise
     */
    @Override
    public boolean containsContext(HttpServletRequest request) {
        String authToken = request.getHeader(JwtUtil.HEADER);
        return null != authToken && !authToken.isEmpty();
    }
}
