package site.yuyanjia.springbootsecuritydemo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * 授权
 *
 * @author seer
 * @date 2019/7/8 15:58
 */
@RestController
@RequestMapping("/authc/")
public class AuthcController {
    private static final Logger log = LoggerFactory.getLogger(AuthcController.class);

    @RequestMapping("/watch")
    public Object watch(Principal principal) {
        String str = Thread.currentThread().getStackTrace()[1].getMethodName() + " " + System.currentTimeMillis();
        log.info("{} {}", principal.getName(), str);
        return str;
    }

    @RequestMapping("/speak")
    public Object speak(Principal principal) {
        String str = Thread.currentThread().getStackTrace()[1].getMethodName() + " " + System.currentTimeMillis();
        log.info("{} {}", principal.getName(), str);
        return str;
    }

    @RequestMapping("/walk")
    public Object walk(Principal principal) {
        String str = Thread.currentThread().getStackTrace()[1].getMethodName() + " " + System.currentTimeMillis();
        log.info("{} {}", principal.getName(), str);
        return str;
    }
}
