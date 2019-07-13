## 信息
* 帐号：yuyanjia
* 密码：yuyanjiademima

## 请求
* 无需授权访问
    * `curl http://127.0.0.1:8080/security-demo/anon/hello-world`
* 未登录
   * `curl -X POST  http://127.0.0.1:8080/security-demo/authc/watch`
* 登录
   * ` curl -H "content-type:application/json" -X POST -c cookie.txt -d "{\"username\": \"yuyanjia\", \"password\": \"yuyanjiademima\"}" http://127.0.0.1:8080/security-demo/authc/login`
* 成功访问
   * `curl -X POST -b cookie.txt http://127.0.0.1:8080/security-demo/authc/watch`
* 权限不足
   * `curl -X POST -b cookie.txt http://127.0.0.1:8080/security-demo/authc/speak`