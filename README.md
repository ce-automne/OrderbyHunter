# OrderbyHunter
一款辅助探测Orderby注入漏洞的BurpSuite插件，Python3编写

#### 1. 支持Get/Post型请求参数的探测，被动探测，对于存在Orderby注入的请求将会在HTTP Histroy里标红


#### 2. 自定义排序参数list，对设置的排序相关参数名自动替换参数值，并使用延迟函数测试SQL注入，延迟函数使用了常用的MySQL数据库里的sleep()
注意：如想测试其他数据库软件PostgreSQL、Oracle，请使用相应的pg_sleep()、dbms_lock.sleep()，未测试，简单替换payload可能不好使


#### 3. 对于请求参数值中出现desc/asc等排序字样的参数名，如未出现在排序参数list里，将会写入文件newOrderByParams.txt，方便后续添加


测试demo可参考我的上一个仓库(https://github.com/ce-automne/OrderbyInjectionDemo)

#### 工具使用效果如下图：

![image](https://user-images.githubusercontent.com/20917372/113467475-c315c380-9475-11eb-9469-1a8a451ecc15.png)


