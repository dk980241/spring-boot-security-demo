package site.yuyanjia.springbootsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import site.yuyanjia.springbootsecuritydemo.dao.WebUserDao;
import site.yuyanjia.springbootsecuritydemo.model.WebUserDO;

import java.util.Set;

/**
 * 用户信息获取service
 *
 * @author seer
 * @date 2018/12/3 14:46
 */
@Service("webUserDetailsService")
public class WebUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private WebUserDao webUserDao;

    /**
     * 根据用户名登录
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        WebUserDO webUserDO = webUserDao.getUserByUsername(username);
        if (null == webUserDO) {
            throw new UsernameNotFoundException("用户登录，用户信息查询失败");
        }
        Set<String> roleSet = webUserDao.listRoleByUserId(webUserDO.getId());

        /**
         封装为框架使用的 userDetail {@link UserDetails}
         */
        WebUserDetail webUserDetail = new WebUserDetail(webUserDO);
        webUserDetail.setRoleSet(roleSet);
        return webUserDetail;
    }
}
