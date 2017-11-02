# webapp
此项目基于[廖雪峰Python3-实战部分](https://www.liaoxuefeng.com/wiki/0014316089557264a6b348958f449949df42a6d3a2e542c000/001432170876125c96f6cc10717484baea0c6da9bee2be4000?t=1509599540274#comments)实现，项目定位是一个由Python实现的个人博客网站。  
项目后端使用**Python3.5**编写，基于**aiohttp**库，并以**Jinja2**作为模板引擎。使用**MySQL**数据库。前端部分使用的是**uikit** CSS框架。内含自己实现的简易**web框架**和**ORM框架**。  

项目实现过程中，自学了**Flask**框架，并用**Flask**和**Bootstrap**框架重构了后端和前端。  
重构后的项目供参考：[myblog](https://github.com/jiyuankai/myblog)

本项目开发相关日志可以在[我的CSDN博客](http://blog.csdn.net/jyk920902)中查看，源码有详细注释供参考~  


## 入口  
**后端API：**  
获取日志：GET /api/blogs  
创建日志：POST /api/blogs  
修改日志：POST /api/blogs/:blog_id  
删除日志：POST /api/blogs/:blog_id/delete  
获取评论：GET /api/comments  
创建评论：POST /api/blogs/:blog_id/comments  
删除评论：POST /api/comments/:comment_id/delete  
创建新用户：POST /api/users  
获取用户：GET /api/users  

**管理页面：**  
评论列表页：GET /manage/comments  
日志列表页：GET /manage/blogs  
创建日志页：GET /manage/blogs/create  
修改日志页：GET /manage/blogs/  
用户列表页：GET /manage/users  

**用户浏览页面：**  
注册页：GET /register  
登录页：GET /signin  
注销页：GET /signout  
首页：GET /  
日志详情页：GET /blog/:blog_id  
