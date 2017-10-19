import orm, asyncio
from models import User, Blog, Comment

loop = asyncio.get_event_loop()
async def test():
	await orm.create_pool(loop, user='root', password='password', db='awesome')
	u = User(name='Test', email='test5@example.com', passwd='12345678990', image='about:blank')
	return await User.findAll()


loop.run_until_complete(test())
loop.close()
