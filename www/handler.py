from models import User, Blog, Comment, next_id
from coroweb import get, post
from aiohttp import web
from config import configs
from apis import APIError, APIValueError, APIPermissionError
import asyncio, time, re, hashlib, json, logging
logging.basicConfig(level=logging.INFO)

COOKIE_NAME = 'awesession' 
_COOKIE_KEY = configs['session']['secret']

_RE_EMAIL = re.compile(r'^[a-zA-Z0-9\.\-\_]+\@[a-zA-Z0-9\-\_]+(\.[a-zA-Z0-9\-\_]+){1,4}$')
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')


# 根据user对象和有效时间，生成cookie值
def user2cookie(user, max_age):
	# id-到期时间-摘要算法
	expires = str(time.time()+max_age)
	s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
	L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
	'''hash = hashlib.sha1(str.encode('utf-8'))
	   hash.hexdigest()'''	
	return '-'.join(L)

async def cookie2user(cookie_str):
	if not cookie_str: # 若cookie不存在
		return None
	try:
		L = cookie_str.split('-')
		if len(L) != 3:
			return None
		uid, expires, sha1 = L
		# 若cookie过期
		if float(expires) < time.time():
			return None
		user = await User.find(uid)
		# 若用户不存在
		if not user:
			return None
		# 用数据库中user信息生成sha1和cookie中的比较
		s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
		if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
			logging.info('Invalid sha1')
			return None
		# 覆盖user的passwd字段
		user.passwd = '******'
		return user
	except Exception as e:
		logging.exception(e)
		return None		
# -------------------------------------------------------用户浏览页面----------------------------------------------------------------
# 主页
@get('/')
def index(request):
	summary = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, \
		sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.'
	blogs = [
		Blog(id='1', name='Test Blog', summary=summary, created_at=time.time()-120),
		Blog(id='1', name='Something New', summary=summary, created_at=time.time()-3600),
		Blog(id='1', name='Learn Swift', summary=summary, created_at=time.time()-7200)
	]
	return {
		'__template__': 'blogs.html',
		'blogs': blogs,
		'__user__': request.__user__
	}

# 注册页面
@get('/register')
def register():
	return { '__template__': 'register.html'}

# 登录页面
@get('/signin')
def signin():
	return {
		'__template__': 'signin.html'
	}
# 登出页面
@get('/signout')
def signout(request):
	referer = request.headers.get('Referer')
	r = web.HTTPFound(referer or '/')
	#清理cookie
	r.set_cookie(COOKIE_NAME, '-deleted-', max_age = 0, httponly = True)
	logging.info('user signed out')
	return r

# -------------------------------------------------------后端api----------------------------------------------------------------

# 用户注册
@post('/api/users')
async def api_register_user(*, name, email, passwd):
	if not name or not name.strip():
		raise APIValueError('name')
	if not email or not _RE_EMAIL.match(email):
		raise APIValueError('email')
	if not passwd or not _RE_SHA1.match(passwd):
		raise APIValueError('passwd')
	users = await User.findAll('email=?', [email])
	# 判断邮箱是否已被注册
	if len(users)>0:
		raise APIError('register: failed', 'email', 'Email is already in use.')
	# 计算密码SHA1散列值需要用到uid，故手动调用next_id
	uid = next_id()
	# 数据库保存uid+密码的SHA1散列值数据
	sha1_passwd = '%s:%s' % (uid, passwd)
	user = User(
		id=uid, 
		name=name.strip(), 
		email=email, 
		passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(),
		# Gravatar是一个第三方头像服务商，能把头像和邮件地址相关联。用户可以到http://www.gravatar.com注册并上传头像。
		# 也可以通过直接在http://www.gravatar.com/avatar/地址后面加上邮箱的MD5散列值获取默认头像。
		image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode('utf-8')).hexdigest()
	)
	await user.save()
	# 制作cookie返回
	r = web.Response()
	r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
	user.passwd = '******' # 在上下文环境中掩盖user对象的passwd字段，并不影响数据库中passwd字段
	r.content_type = 'application/json'
	r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
	return r

# 用户登录
@post('/api/authenticate')
async def authenticate(*, email, passwd):
	if not email:
		raise APIValueError('email', 'Invalid email.')
	if not passwd:
		raise APIValueError('passwd', 'Invalid password.')
	users = await User.findAll('email=?', [email])
	if len(users) == 0:
		raise APIValueError('email', 'Emial not exist.')
	user = users[0] # findAll返回的是仅含一个user对象的list
	# 把用户输入的密码进行摘要算法
	sha1_passwd = '%s:%s' % (user.id, passwd)
	# 与数据库中密码进行比较
	if hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest() != user.passwd:
		raise APIValueError('passwd', 'Invalid password.')
	# 重置cookie，返回给客户端
	r = web.Response()
	r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
	user.passwd = '******' 
	r.content_type = 'application/json'
	r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
	return r	

