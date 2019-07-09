package site.yuyanjia.springbootsecuritydemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 启动类
 *
 * @author seer
 * @date 2019/7/8 11:37
 */
@SpringBootApplication
public class SpringBootSecurityDemoApplication {
    private static final Logger log = LoggerFactory.getLogger(SpringBootSecurityDemoApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityDemoApplication.class, args);
        log.warn("================= 启动完成 ==============");
    }

}
