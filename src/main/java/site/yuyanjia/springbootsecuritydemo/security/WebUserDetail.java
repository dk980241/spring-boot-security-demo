package site.yuyanjia.springbootsecuritydemo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import site.yuyanjia.springbootsecuritydemo.model.WebUserDO;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 扩展默认的 UserDetails
 * <p>
 * 支持更多自定义的字段
 *
 * @author seer
 * @date 2018/12/6 12:00
 */
public class WebUserDetail extends WebUserDO implements UserDetails {

    /**
     * 角色
     */
    private Set<String> roleSet;

    public WebUserDetail() {
    }

    public WebUserDetail(WebUserDO webUserDO) {
        super.id = webUserDO.getId();
        super.username = webUserDO.getUsername();
        super.password = webUserDO.getPassword();
        super.salt = webUserDO.getSalt();
        super.mobile = webUserDO.getMobile();
        super.realName = webUserDO.getRealName();
        super.locked = webUserDO.getLocked();
        super.gmtCreate = webUserDO.getGmtCreate();
        super.gmtModified = webUserDO.getGmtModified();
    }

    /**
     * 获取权限信息
     *
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        /*
        将角色信息封装为框架要求格式
         */
        if (roleSet == null) {
            return null;
        }
        return roleSet.stream().map(
                s -> new SimpleGrantedAuthority(s)
        ).collect(Collectors.toSet());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Set<String> getRoleSet() {
        return roleSet;
    }

    public void setRoleSet(Set<String> roleSet) {
        this.roleSet = roleSet;
    }

    @Override
    public String toString() {
        return "WebUserDetail{" +
                "roleSet=" + roleSet +
                "} " + super.toString();
    }
}
