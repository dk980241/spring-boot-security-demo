package site.yuyanjia.springbootsecuritydemo.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * JwtUtil
 * <p>
 * TOKEN： eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ5dXlhbmppYSIsImlhdCI6MTU5NDg2NTgyNSwiZXhwIjoxNTk1NDcwNjI0fQ.jrSiu-2AcTJfk5KZlecdFyjr3_JXjfNtrcAXIxyDDbE
 * 组成： HEADER.PAYLOAD.SIGNATURE
 * 翻译：
 * HEADER: { "alg": "HS256" }
 * PAYLOAD: { "sub": "yuyanjia", "iat": 1594865825, "exp": 1595470624 }
 * SIGNATURE: HMACSHA256( base64UrlEncode(header) + "." + base64UrlEncode(payload),SECRET)
 *
 * @author seer
 * @date 2020/7/16 8:59
 */
public class JwtUtil {
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * token 有效时间我 7天
     */
    private final static long TOKEN_LIFETIME = 1000L * 60 * 60 * 24 * 7;

    /**
     * 算法
     */
    private final static SignatureAlgorithm ALGORITHM = SignatureAlgorithm.HS256;

    /**
     * 密钥
     */
    private final static String SECRET = "1234-abcd-DCBA-4321";

    /**
     * token head
     */
    public final static String HEADER = "Authorization";

    /**
     * 获取用户名
     *
     * @param token token
     * @return object
     */
    public static String getUserName(String token) {
        Claims claims = parseToken(token);
        return claims.getSubject();
    }


    /**
     * token 是否有效
     *
     * @param token token
     * @return true 有效
     */
    public static boolean isValid(String token) {
        Date expiredDate;
        try {
            expiredDate = parseToken(token).getExpiration();
        } catch (SignatureException e) {
            if (log.isDebugEnabled()) {
                log.debug("签名验证失败");
            }
            return false;
        }
        return expiredDate.after(new Date());
    }

    /**
     * 生成token
     * <p>
     * iss: jwt签发者
     * sub: jwt所面向的用户
     * aud: 接收jwt的一方
     * exp: jwt的过期时间，这个过期时间必须要大于签发时间
     * nbf: 定义在什么时间之前，该jwt都是不可用的
     * iat: jwt的签发时间
     * jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
     *
     * @param username username
     * @return object
     */
    public static String generateToken(String username) {
        Date expireDate = new Date(System.currentTimeMillis() + TOKEN_LIFETIME);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(ALGORITHM, SECRET)
                .compact();
    }

    /**
     * 解析token
     * <p>
     * 验签失败 {@link io.jsonwebtoken.SignatureException}
     *
     * @param token token
     * @return object
     */
    private static Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
