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
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
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
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import site.yuyanjia.springbootsecuritydemo.dao.WebUserDao;
import site.yuyanjia.springbootsecuritydemo.security.WebUserDetail;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * 安全配置
 *
 * @author seer
 * @date 2018/12/5 10:30
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

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
     * 授权 URL
     */
    private static final String AUTH_URL_REG = AUTH_URL + "**";

    /**
     * 登录用户名
     */
    private static final String LOGIN_NAME = "username";

    /**
     * 登录密码
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
                .cors().and()
                // 跨域伪造请求限制.无效
                .csrf().disable()
                /*
                异常处理
                默认 权限不足  返回403，可以在这里自定义返回内容
                 */
                .exceptionHandling().accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> {
            log.info("权限不足 [{}]", e.getMessage());
            httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            httpServletResponse.getWriter().write(ROLE_LIMIT);
        })
                .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
                    log.info("登录过期 [{}]", e.getMessage());
                    httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    httpServletResponse.getWriter().write(LOGIN_EXPIRE);
                }).and()
                // 开启授权认证
                .authorizeRequests()
                // 需要授权访问的
                .antMatchers(AUTH_URL_REG).authenticated()
                // OPTIONS预检请求不处理
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                // 其他请求不处理
                .anyRequest().permitAll()
                // 这里可以用来设置权限验证处理，由于设置了这里，所以上述权限路径设置，实际不起作用。
                .withObjectPostProcessor(new DefinedObjectPostProcessor())
                .and()
                .logout().logoutUrl(LOGOUT_URL).invalidateHttpSession(true).clearAuthentication(true)
                .logoutSuccessHandler((request, response, authentication) -> {
                    log.info("注销成功 [{}]", null != authentication ? authentication.getName() : null);
                    response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    response.getWriter().write(SUCCESS);
                })
                .and()
                // reqeust，session缓存，自行实现 org.springframework.security.web.savedrequest.RequestCache
                .requestCache().requestCache(new HttpSessionRequestCache())
                .and()
                // 实现 json 登录
                .addFilter(getJsonFilter(super.authenticationManager()));
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
     *
     * @return
     */
    private AbstractAuthenticationProcessingFilter getJsonFilter(AuthenticationManager authenticationManager) {
        AbstractAuthenticationProcessingFilter filter = new JsonAuthenticationFilter();

        // 登录成功后
        filter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            log.info("用户登录成功 [{}]", authentication.getName());
            // 获取登录成功信息
            httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            httpServletResponse.getWriter().write(SUCCESS);
        });
        //登录失败后
        filter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.info("用户登录失败 [{}]", e.getMessage());
            httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            httpServletResponse.getWriter().write(FAILED);
        });
        // 作用在登录的URL
        filter.setFilterProcessesUrl(LOGIN_URL);
        // 设置验证manager
        filter.setAuthenticationManager(authenticationManager);
        return filter;
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

    /**
     * 权限处理
     */
    class DefinedObjectPostProcessor implements ObjectPostProcessor<FilterSecurityInterceptor> {
        @Override
        public <O extends FilterSecurityInterceptor> O postProcess(O object) {
            /*
               设置权限原数据
               这里为，请求URL归属哪个角色，最终要用对角色做比较
             */
            object.setSecurityMetadataSource(new FilterInvocationSecurityMetadataSource() {
                @Override
                public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
                    String requestUrl = ((FilterInvocation) o).getRequestUrl();
                    // 不需要授权路径
                    if (!requestUrl.startsWith(AUTH_URL)) {
                        if (log.isDebugEnabled()) {
                            log.debug("[{}] permit all", requestUrl);
                        }
                        return null;
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
            });

            /*
            设置权限决策者
            是否有访问权限在这里确定的
             */
            object.setAccessDecisionManager(new AccessDecisionManager() {
                /**
                 * 判定
                 *
                 * @param authentication 登录用户的信息
                 * @param o
                 * @param collection   请求地址拥有的角色集合
                 * @throws AccessDeniedException
                 * @throws InsufficientAuthenticationException
                 */
                @Override
                public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
                    Iterator<ConfigAttribute> iterator = collection.iterator();
                    while (iterator.hasNext()) {
                        ConfigAttribute attribute = iterator.next();
                        Collection<? extends GrantedAuthority> authenticationAuthorities = authentication.getAuthorities();
                        for (GrantedAuthority authenticationAuthority : authenticationAuthorities) {
                            if (authenticationAuthority.getAuthority().equalsIgnoreCase(attribute.getAttribute())) {
                                return;
                            }
                        }
                    }
                    throw new AccessDeniedException("权限不足");
                }

                @Override
                public boolean supports(ConfigAttribute configAttribute) {
                    return true;
                }

                @Override
                public boolean supports(Class<?> aClass) {
                    return true;
                }
            });
            return object;
        }
    }

}
