package site.yuyanjia.springbootsecuritydemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import site.yuyanjia.springbootsecuritydemo.dao.WebUserDao;
import site.yuyanjia.springbootsecuritydemo.security.WebUserDetail;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * jwt 安全配置
 * <p>
 * 基于form表单
 *
 * @author seer
 * @date 2020/7/16 10:01
 */
@Configuration
@EnableWebSecurity
@SuppressWarnings("all")
public class JwtWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(JwtWebSecurityConfig.class);

    /**
     * 成功
     */
    private static final String SUCCESS = "{\"result_code\": \"00000\", \"result_msg\": \"处理成功\"}";

    /**
     * 失败
     */
    private static final String FAILED = "{\"result_code\": \"99999\", \"result_msg\": \"处理失败\"}";

    /**
     * 登录过期
     */
    private static final String LOGIN_EXPIRE = "{\"result_code\": \"10001\", \"result_msg\": \"登录过期\"}";

    /**
     * 权限限制
     */
    private static final String ROLE_LIMIT = "{\"result_code\": \"10002\", \"result_msg\": \"权限不足\"}";

    /**
     * 登录 URL
     */
    private static final String LOGIN_URL = "/authc/login";

    /**
     * 登出 URL
     */
    private static final String LOGOUT_URL = "/authc/logout";

    /**
     * 授权 URL
     */
    private static final String AUTH_URL = "/authc/";

    /**
     * 授权 URL 正则
     */
    private static final String AUTH_URL_REG = AUTH_URL + "**";

    /**
     * 登录用户名参数名
     */
    private static final String LOGIN_NAME = "username";

    /**
     * 登录密码参数名
     */
    private static final String LOGIN_PWD = "password";

    /**
     * 记住登录参数名
     */
    private static final String REMEMBER_ME = "rememberMe";

    /**
     * token有效时间10天
     * 框架实现 {@link RememberMeConfigurer#tokenValiditySeconds}
     * 此处使用redis实现
     */
    private static final Long TOKEN_VALID_DAYS = 10L;

    @Autowired
    private UserDetailsService webUserDetailsService;

    @Autowired
    private WebUserDao webUserDao;

    @Autowired
    private RedisTemplate redisTemplate;

    /**
     * cors跨域
     *
     * @return object
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(3600L);
        corsConfiguration.addExposedHeader("access-control-allow-methods");
        corsConfiguration.addExposedHeader("access-control-allow-headers");
        corsConfiguration.addExposedHeader("access-control-allow-origin");
        corsConfiguration.addExposedHeader("access-control-max-age");
        corsConfiguration.addExposedHeader("X-Frame-Options");

        UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
        configurationSource.registerCorsConfiguration(AUTH_URL_REG, corsConfiguration);
        return configurationSource;
    }

    /**
     * http安全配置
     * <p>
     * 使用原生form表单登录 {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter}
     * 使用jwt 维护用户状态 {@link JwtSecurityContextRepository}
     * 登录成功生成jwt {@link DefinedAuthenticationSuccessHandler}
     * <p>
     * {@link SecurityContextPersistenceFilter}
     * {@link SessionManagementFilter}
     * 默认使用 {@link HttpSessionSecurityContextRepository} 基于session管理用户信息
     * <p>
     * jwt不基于服务端状态，
     * 自定义{@link JwtSecurityContextRepository}维护用户信息
     *
     * @param http http
     * @throws Exception exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable();

        http
                .exceptionHandling()
                .accessDeniedHandler(new DefinedAccessDeniedHandler())
                .authenticationEntryPoint(new DefinedAuthenticationEntryPoint());

        http
                .authorizeRequests()
                .accessDecisionManager(accessDecisionManager())
                .withObjectPostProcessor(new DefindeObjectPostProcessor());

        http
                .authorizeRequests()
                .antMatchers(AUTH_URL_REG).authenticated()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .anyRequest().permitAll();

        http
                .formLogin()
                .usernameParameter(LOGIN_NAME)
                .passwordParameter(LOGIN_PWD)
                .loginProcessingUrl(LOGIN_URL)
                .successHandler(new DefinedAuthenticationSuccessHandler())
                .failureHandler(new DefindeAuthenticationFailureHandler());

        http
                .logout()
                .logoutUrl(LOGOUT_URL)
                .invalidateHttpSession(true)
                .invalidateHttpSession(true)
                .logoutSuccessHandler(new DefinedLogoutSuccessHandler());

        // 详见注释
        http
                .addFilterAt(new SecurityContextPersistenceFilter(new JwtSecurityContextRepository()), SecurityContextPersistenceFilter.class)
                .addFilterAt(new SessionManagementFilter(new JwtSecurityContextRepository()), SessionManagementFilter.class);
    }

    /**
     * 配置登录验证
     *
     * @param auth auth
     * @throws Exception exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(webUserDetailsService);
        auth.authenticationProvider(new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String loginUsername = authentication.getName();
                String loginPassword = (String) authentication.getCredentials();
                log.info("用户登录，用户名 [{}]，密码 [{}]", loginUsername, loginPassword);

                WebUserDetail webUserDetail = (WebUserDetail) webUserDetailsService.loadUserByUsername(loginUsername);
                // 此处自定义密码加密处理规则
                if (!loginPassword.equals(webUserDetail.getPassword())) {
                    throw new DisabledException("用户登录，密码错误");
                }

                return new UsernamePasswordAuthenticationToken(webUserDetail, webUserDetail.getPassword(), webUserDetail.getAuthorities());
            }

            /**
             * 支持使用此方法验证
             *
             * @param aClass aClass
             * @return 没有特殊处理，返回true，否则不会用这个配置进行验证
             */
            @Override
            public boolean supports(Class<?> aClass) {
                return true;
            }
        });
    }

    /**
     * 决策管理
     * {@link AffirmativeBased} 有一个赞成即可通过
     * {@link UnanimousBased} 不适用同权限归属多角色场景
     *
     * @return object
     */
    private AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new UrlRoleVoter());
        AffirmativeBased based = new AffirmativeBased(decisionVoters);
        return based;
    }

    class DefindeObjectPostProcessor implements ObjectPostProcessor<FilterSecurityInterceptor> {
        @Override
        public <O extends FilterSecurityInterceptor> O postProcess(O object) {
            object.setSecurityMetadataSource(new DefinedFilterInvocationSecurityMetadataSource());
            return object;
        }
    }

    /**
     * {@link org.springframework.security.access.vote.RoleVoter}
     */
    class UrlRoleVoter implements AccessDecisionVoter<Object> {

        @Override
        public boolean supports(ConfigAttribute attribute) {
            if (null == attribute.getAttribute()) {
                return false;
            }
            return true;
        }

        @Override
        public boolean supports(Class<?> clazz) {
            return true;
        }

        @Override
        public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
            if (null == authentication) {
                return ACCESS_DENIED;
            }
            int result = ACCESS_ABSTAIN;
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            for (ConfigAttribute attribute : attributes) {
                if (this.supports(attribute)) {
                    result = ACCESS_DENIED;
                    for (GrantedAuthority authority : authorities) {
                        if (attribute.getAttribute().equals(authority.getAuthority())) {
                            return ACCESS_GRANTED;
                        }
                    }
                }
            }
            return result;
        }
    }

    /**
     * 权限验证数据源
     * <p>
     * 此处实现
     * 从数据库中获取URL对应的role信息
     */
    class DefinedFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
        @Override
        public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
            String requestUrl = ((FilterInvocation) o).getRequestUrl();
            // 不需要授权的URL 无需查询归属角色
            if (!requestUrl.startsWith(AUTH_URL)) {
                return SecurityConfig.createList();
            }
            List<String> roleIds = webUserDao.listRoleByUrl(requestUrl);
            return SecurityConfig.createList(roleIds.toArray(new String[0]));
        }

        @Override
        public Collection<ConfigAttribute> getAllConfigAttributes() {
            return null;
        }

        @Override
        public boolean supports(Class<?> aClass) {
            return FilterInvocation.class.isAssignableFrom(aClass);
        }
    }

    /**
     * 权限拒绝handler
     */
    class DefinedAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            if (log.isDebugEnabled()) {
                log.debug("权限不足 [{}]", accessDeniedException.getMessage());
            }
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(ROLE_LIMIT);
        }
    }

    /**
     * 授权入口
     * 登录过期
     */
    class DefinedAuthenticationEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            if (log.isDebugEnabled()) {
                log.debug("登录过期 [{}]", authException.getMessage());
            }
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(LOGIN_EXPIRE);
        }
    }

    /**
     * 授权成功handler
     */
    class DefinedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
            // jwt token
            String token = JwtUtil.generateToken(authentication.getName(), roles);
            log.info("用户登录成功 {} {} {}", authentication.getName(), authentication.getAuthorities(), token);
            response.setHeader(JwtUtil.HEADER, token);
            // 获取登录成功信息
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(SUCCESS);
        }
    }

    /**
     * 授权失败handler
     */
    class DefindeAuthenticationFailureHandler implements AuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            log.info("用户登录失败 [{}]", exception.getMessage());
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(FAILED);
        }
    }

    /**
     * 注销成功hanlder
     */
    class DefinedLogoutSuccessHandler implements LogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            log.info("注销成功 [{}]", null != authentication ? authentication.getName() : null);
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(SUCCESS);
        }
    }

    /**
     * JwtSecurityContextRepository
     */
    class JwtSecurityContextRepository implements SecurityContextRepository {

        @Override
        public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
            HttpServletRequest request = requestResponseHolder.getRequest();
            String authToken = request.getHeader(JwtUtil.HEADER);
            if (null == authToken) {
                if (log.isDebugEnabled()) {
                    log.debug("No SecurityContext was available, A new one will be created.");
                }
                return SecurityContextHolder.createEmptyContext();
            }

            if (!JwtUtil.isValid(authToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("jwt 无效");
                }
                return SecurityContextHolder.createEmptyContext();
            }
            String username = JwtUtil.getUserName(authToken);
            Set<SimpleGrantedAuthority> roleSet = JwtUtil.getRoles(authToken);
            if (log.isDebugEnabled()) {
                log.debug("jwt username {} {}", username, roleSet);
            }
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(username, roleSet);
            securityContext.setAuthentication(authenticationToken);
            return securityContext;
        }

        @Override
        public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
            if (log.isDebugEnabled()) {
                log.debug("jwt 无需服务端保存状态");
            }
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

    /**
     * JwtAuthenticationToken
     */
    class JwtAuthenticationToken extends AbstractAuthenticationToken {
        private String username;

        /**
         * init
         *
         * @param username    用户名
         * @param authorities 角色
         */
        public JwtAuthenticationToken(String username, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.username = username;
        }

        /**
         * jwt 已做验证 {@link JwtUtil#isValid(String)}
         *
         * @return object
         */
        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return username;
        }

        /**
         * jwt 已做验证 {@link JwtUtil#isValid(String)}
         *
         * @return true
         */
        @Override
        public boolean isAuthenticated() {
            return true;
        }
    }
}
