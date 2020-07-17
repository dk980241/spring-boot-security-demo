## 信息
* 帐号：yuyanjia
* 密码：yuyanjiademima

## 请求
* 无需授权访问
    * `curl http://127.0.0.1:8080/security-demo/anon/hello-world`
* 未登录
   * `curl -i -X POST http://127.0.0.1:8080/security-demo/authc/watch`
* 登录 json
   * `curl -i -H "content-type:application/json" -X POST -c cookie.txt -d "{\"username\": \"yuyanjia\", \"password\": \"yuyanjiademima\"}" http://127.0.0.1:8080/security-demo/authc/login`
* 登录 form jwt
   * `curl -i -H "content-type:application/x-www-form-urlencoded" -X POST -c cookie.txt -d "username=yuyanjia&password=yuyanjiademima&rememberMe=true" http://127.0.0.1:8080/security-demo/authc/login`
* 成功访问
   * `curl -i -X POST -b cookie.txt http://127.0.0.1:8080/security-demo/authc/watch`
* 成功访问 jwt
   * `curl -i -H "Authorization:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ5dXlhbmppYSIsImlhdCI6MTU5NDk3OTU5OSwiZXhwIjoxNTk1NTg0Mzk5LCJyb2xlcyI6WyJ3YXRjaCJdfQ.YY4j2FtfJRXvs5CJjZczUeFA_7sO274YceKXvCwmMms" -X POST http://127.0.0.1:8080/security-demo/authc/watch`
* 权限不足
   * `curl -i -X POST -b cookie.txt http://127.0.0.1:8080/security-demo/authc/speak`
