package site.yuyanjia.springbootsecuritydemo.dao;

import site.yuyanjia.springbootsecuritydemo.model.WebUserDO;

import java.util.List;
import java.util.Set;

/**
 * 用户dao
 *
 * @author seer
 * @date 2019/7/8 14:53
 */
public interface WebUserDao {

    /**
     * 根据用户名查询
     *
     * @param username
     * @return
     */
    WebUserDO getUserByUsername(String username);

    /**
     * 查询用户角色
     *
     * @param id
     * @return
     */
    Set<String> listRoleByUserId(Long id);

    /**
     * 查询url所属角色
     *
     * @param url
     * @return
     */
    List<String> listRoleByUrl(String url);
}
