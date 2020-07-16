package site.yuyanjia.springbootsecuritydemo.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.*;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.*;
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
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import site.yuyanjia.springbootsecuritydemo.dao.WebUserDao;
import site.yuyanjia.springbootsecuritydemo.security.WebUserDetail;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 安全配置
 * <p>
 * json
 *
 * @author seer
 * @date 2018/12/5 10:30
 */
// @Configuration
// @EnableWebSecurity
@SuppressWarnings("all")
public class JsonWebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(JsonWebSecurityConfig.class);

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
     * 登录用户名参数名
     */
    private static final String LOGIN_NAME = "username";

    /**
     * 登录密码参数名
     */
    private static final String LOGIN_PWD = "password";

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
                // 开启跨域共享
                .cors()
                .and()
                // 跨域伪造请求限制.无效
                .csrf().disable();

        http
                /*
                异常处理
                默认 权限不足  返回403，可以在这里自定义返回内容
                 */
                .exceptionHandling()
                .accessDeniedHandler(new DefinedAccessDeniedHandler())
                .authenticationEntryPoint(new DefinedAuthenticationEntryPoint());

        http
                /**
                 *权限验证配置项
                 */
                .authorizeRequests()
                .accessDecisionManager(accessDecisionManager())
                .withObjectPostProcessor(new DefindeObjectPostProcessor());

        http
                // 开启授权认证
                .authorizeRequests()
                // 需要授权访问的
                .antMatchers(AUTH_URL_REG).authenticated()
                // OPTIONS预检请求不处理
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                // 其他请求不处理
                .anyRequest().permitAll();

        http
                .logout()
                .logoutUrl(LOGOUT_URL)
                .invalidateHttpSession(true)
                .invalidateHttpSession(true)
                .logoutSuccessHandler(new DefinedLogoutSuccessHandler());

        http
                // 实现 json 登录
                .addFilterAt(getJsonFilter(super.authenticationManager()), UsernamePasswordAuthenticationFilter.class);


    }

    /**
     * 配置登录验证
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 用户信息获取service
        auth.userDetailsService(webUserDetailsService);
        // 自定义的密码验证
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
     * 获取json授权filter
     * <p>
     * rememberMe的实现需要做大量的自定义代码
     * {@link org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices#rememberMeRequested}
     * 在登录过程中将rememberMe的属性放到 attribute 中
     * 在rememberMeSeriveces 中从 attribute中获取值
     *
     * @return
     */
    private AbstractAuthenticationProcessingFilter getJsonFilter(AuthenticationManager authenticationManager) {
        AbstractAuthenticationProcessingFilter filter = new JsonAuthenticationFilter();

        // 登录成功后
        filter.setAuthenticationSuccessHandler(new DefinedAuthenticationSuccessHandler());
        //登录失败后
        filter.setAuthenticationFailureHandler(new DefindeAuthenticationFailureHandler());
        // 作用在登录的URL
        filter.setFilterProcessesUrl(LOGIN_URL);
        // 设置验证manager
        filter.setAuthenticationManager(authenticationManager);

        filter.setRememberMeServices(new NullRememberMeServices());
        return filter;
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
        AffirmativeBased based = new AffirmativeBased(decisionVoters);
        return based;
    }

    /**
     * json 登录 filter
     */
    class JsonAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

        /**
         * 获取json数据格式的用户名和密码
         *
         * @param request
         * @param response
         * @return
         * @throws AuthenticationException
         */
        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            if (!request.getMethod().equalsIgnoreCase(HttpMethod.POST.toString())) {
                // 不支持的请求方式
                throw new AuthenticationServiceException("不支持的请求方式: " + request.getMethod());
            }
            if (!MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(request.getContentType())
                    && !MediaType.APPLICATION_JSON_UTF8_VALUE.equalsIgnoreCase(request.getContentType())) {
                throw new AuthenticationServiceException("不支持的请求内容格式: " + request.getContentType());
            }
            // 解析request内容
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setExpandEntityReferences(false);
            StringBuffer sb = new StringBuffer();
            try (InputStream inputStream = request.getInputStream(); BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                String str;
                while ((str = bufferedReader.readLine()) != null) {
                    sb.append(str);
                }
            } catch (IOException ex) {
                throw new RuntimeException("获取请求内容异常", ex);
            }

            JSONObject jsonObject = JSON.parseObject(sb.toString());
            String username = jsonObject.getString(LOGIN_NAME);
            String password = jsonObject.getString(LOGIN_PWD);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            return this.getAuthenticationManager().authenticate(authenticationToken);
        }
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
