package site.yuyanjia.springbootsecuritydemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
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
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;
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

/**
 * 默认安全配置
 * <p>
 * form表单
 *
 * @author seer
 * @date 2019/7/21 9:30
 */
@Configuration
@EnableWebSecurity
@SuppressWarnings("all")
public class FormWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(FormWebSecurityConfig.class);

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
    private static final String AUTH_URL_REG = "/authc/**";

    /**
     * 登录用户名
     */
    private static final String LOGIN_NAME = "username";

    /**
     * 登录密码
     */
    private static final String LOGIN_PWD = "password";

    /**
     * 记住登录
     */
    private static final String REMEMBER_ME = "rememberMe";

    @Autowired
    private UserDetailsService webUserDetailsService;

    @Autowired
    private WebUserDao webUserDao;

    /**
     * cors跨域
     *
     * @return
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
     *
     * @param http
     * @throws Exception
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

        http
                .rememberMe()
                .rememberMeParameter(REMEMBER_ME)
                .rememberMeServices(new SpringSessionRememberMeServices());

    }


    /**
     * 配置登录验证
     *
     * @param auth
     * @throws Exception
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
             * @param aClass
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
     *
     * @return
     */
    private AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new AuthenticatedVoter());
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new UrlRoleVoter());
        UnanimousBased based = new UnanimousBased(decisionVoters);
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
     * 数据源
     */
    class DefinedFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
        @Override
        public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
            String requestUrl = ((FilterInvocation) o).getRequestUrl();
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
     * 权限handler
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
     * 授权handler
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
            log.info("用户登录成功 [{}]", authentication.getName());
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
     * 登出成功hanlder
     */
    class DefinedLogoutSuccessHandler implements LogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            log.info("注销成功 [{}]", null != authentication ? authentication.getName() : null);
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(SUCCESS);
        }
    }
}
