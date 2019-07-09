package site.yuyanjia.springbootsecuritydemo.dao.impl;

import org.springframework.stereotype.Service;
import site.yuyanjia.springbootsecuritydemo.dao.WebUserDao;
import site.yuyanjia.springbootsecuritydemo.model.WebUserDO;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 用户查询
 * <p>
 * 伪装数据库查询
 *
 * @author seer
 * @date 2019/7/8 14:58
 */
@Service("webUserDao")
public class WebUserDaoImpl implements WebUserDao {

    /**
     * 更具用户名查询
     *
     * @param username
     * @return
     */
    @Override
    public WebUserDO getUserByUsername(String username) {
        if ("yuyanjia".equals(username)) {
            WebUserDO webUserDO = new WebUserDO();
            webUserDO.setId(1L);
            webUserDO.setUsername("yuyanjia");
            webUserDO.setPassword("yuyanjiademima");
            webUserDO.setSalt("334D1C2486484CBB822C6FCF45C876C8");
            return webUserDO;
        }
        return null;
    }

    /**
     * 查询用户角色
     *
     * @param id
     * @return
     */
    @Override
    public Set<String> listRoleByUserId(Long id) {
        Set<String> roleSet = new HashSet<>();
        roleSet.add("watch");
        return roleSet;
    }

    /**
     * 查询url所属角色
     *
     * @param url
     * @return
     */
    @Override
    public List<String> listRoleByUrl(String url) {
        List<String> roleList = new ArrayList<>();
        if ("/authc/watch".equals(url)) {
            roleList.add("watch");
            return roleList;
        }
        if ("/authc/speak".equals(url)) {
            roleList.add("speak");
            return roleList;
        }
        if ("/authc/walk".equals(url)) {
            roleList.add("watch");
            roleList.add("speak");
            return roleList;
        }
        return roleList;
    }
}
