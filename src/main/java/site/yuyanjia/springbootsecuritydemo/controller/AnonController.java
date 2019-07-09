package site.yuyanjia.springbootsecuritydemo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 无需授权
 *
 * @author seer
 * @date 2019/7/8 15:57
 */
@RestController
@RequestMapping("/anon/")
public class AnonController {
    private static final Logger log = LoggerFactory.getLogger(AnonController.class);

    @RequestMapping("/hello-world")
    public Object helloWorld() {
        String str = Thread.currentThread().getStackTrace()[1].getMethodName() + " " + System.currentTimeMillis();
        log.info("{}", str);
        return str;
    }
}
