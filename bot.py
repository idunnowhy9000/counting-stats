import praw
from praw.helpers import flatten_tree
import re
import sqlite3
from datetime import datetime
import argparse
from math import floor

# Counting subreddit
SUBREDDIT = 'counting'
# Bot's useragent
USERAGENT = 'Statistics for /r/counting by idunnowhy9000'
# List of thread names, you can add or remove threads to track
THREAD_NAME = 'main'
# Base regex for base 10 threads
BASE_REGEX = r'^\W*(\d+(\W*\d+)*|\d+)'

class Thread(object):
	
	def __init__(self, search='', tid=False, regex=BASE_REGEX, base=10, group=0, flags=0, check=None):
		self.search = search
		self.tid = tid
		self.base = base
		
		self.group = group
		self.flags = flags
		self.regex = re.compile(regex, flags=flags)
		
		self.threads = []
	
	def match(self, text):
		return self.regex.match(text)
	
	def parse(self, matches):
		if self.base:
			return int(re.sub(r'\W', '', matches.group(self.group)), self.base)
		else:
			return re.sub(r'\W', '', matches.group(self.group))
	
	def search_thread(self, r):
		threads = []
		if self.tid:
			if type(self.tid) == list:
				for id in self.tid:
					threads.append(r.get_submission(submission_id=id))
			else:
				threads.append(r.get_submission(submission_id=self.tid))
		else:
			for search in subreddit.search(self.search, sort='new'):
				tid = search.id
				if tid in self.exception:
					continue
					
				threads.append(search)
			
		return threads

# Thread options
THREAD_OPTIONS = {
	'main': {
		'search': 'title:Counting Thread',
		'tid': ['3xiune']
	},
	'alphanumeric': {
		'search': 'title:Alphanumerics',
		'regex': '^\W*([0-9A-Z]+)',
		'base': 36
	},
	'sheep':{
		'search':'title:Sheep',
		'tid': ['3tipxx', '3fzm7p', '3pydtg']
	},
	'letters': {
		'search':'title:letters',
		'regex': '^\W*([A-Z]+)'
	},
	'updown': {
		'search':'(title:up down) OR (title:increment decrement) OR (title:tug of war)',
		'regex': r'^\W*(-?\d+([,\.\s_]\d+)*|\d+)'
	},
	'palindrome': {
		'search':'title:palindrome NOT (title:hexadecimal OR title:hex OR title:binary)',
		'tid': ['3ujvpp']
	},
	'hexadecimal': {
		'search':'(title:hexadecimal OR title:hex) NOT title:palindrome',
		'regex': r'^\W*(?:0[xX])?([0-9a-fA-F]+)',
		'base': 16
	},
	'palindrome-hex': {
		'search':'title:hexadecimal palindrome OR title:hex palindrome',
		'regex': r'^\W*(?:0[xX])?([0-9a-fA-F]+)',
		'base': 16
	},
	'time': {
		'search':'title:time counting thread',
		'regex': r'^\W*(\d{1,2})\W*(\d{1,2})\W*(\d{1,2})\W*(AM|PM)?'
	},
	'binary': {
		'search': 'title:binary NOT title:palindrome',
		'regex': r'^\W*([01,\.\s]+)',
		'base': 2
	},
	'ternary': {
		'search': 'title:ternary counting thread',
		'regex': r'^\W*([012,\.\s]+)',
		'tid': ['3unkpu'],
		'base': 3
	},
	'roman': {
		'tid': '3smutv',
		'regex': '^[~`#*_\\s\\[>~]*([\u2182\u2181MDCLXVI\\W]+)'
	},
	'12345': {
		'regex': '^(\D*1\D*2\D*3\D*4\D*5\D*)(=\W*\d+(\W*\d+)*|\d+)?',
		'group': 2
	},
	'fourfours': {
		'regex': '^(\D*4){4}\D*=\W*(\d+(\W*\d+)*|\d+)',
		'group': 2
	},
	'gr8b8m8': {
		'regex':'^\W*(gr\W*\d+\W*b\W*\d+\W*m\W*\d+)',
		'tid': '3mwb6g',
		'group': 1,
		'flags': re.I
	}
}

# Compile classes
THREAD = Thread(**THREAD_OPTIONS[THREAD_NAME])

# Filter database
FILTER = ''

# Infinite representation
try:
	from math import inf
except ImportError:
	inf = float('inf')

print('Opening SQL Database')
sql = sqlite3.connect('sql.db', detect_types=sqlite3.PARSE_DECLTYPES)
sql.create_function('contains_69', 1, lambda n: '69' in n)
sql.create_function('ends_69', 1, lambda n: n[::2])

cur = sql.cursor()

cur.execute('CREATE TABLE IF NOT EXISTS {}(id TEXT, value TEXT, author TEXT, time DATETIME)'.format(THREAD_NAME))
cur.execute('CREATE TABLE IF NOT EXISTS stats_{}(author TEXT, counts INT)'.format(THREAD_NAME))

def setup_reddit():
	# Good to go
	r = praw.Reddit(USERAGENT)

	try:
		import login
		r.login(login.USERNAME, login.PASSWORD)
	except ImportError:
		pass
	
	return r

def replybot():
	threads = THREAD.search_thread(setup_reddit())
	
	for thread in threads:
		_max = -inf
		_min = inf
		
		valid = bad = skipped = deleted = 0
		authorsByValues = {}
		duplicates = []
		
		print(thread)
		comments = thread.comments
		
		for comment in comments:
			
			if isinstance(comment, praw.objects.MoreComments):
				comments.extend(comment.comments())
				continue
			
			# Extend comments with replies for loop
			comments.extend(comment.replies)
			
			pid = comment.id
			pbody = comment.body
			pdate = int(comment.created_utc)

			try:
				pauthor = comment.author.name
			except AttributeError:
				# Author is deleted. We don't care about this post.
				deleted += 1
				continue
			
			cur.execute('SELECT * FROM `{}` WHERE ID=?'.format(THREAD_NAME), [pid])
			if cur.fetchone():
				# Post is already in the database
				continue
			
			matches = THREAD.match(pbody)
				
			if not matches:
				skipped += 1
				print('Skipped:', pbody.encode('utf8'))
				continue
			
			try:
				value = THREAD.parse(matches)
			except ValueError as e:
				bad += 1
				print(e)
				continue
			
			cur.execute('SELECT * FROM `{}` WHERE value=?'.format(THREAD_NAME), [value])
			if (value in authorsByValues) or cur.fetchone():
				duplicates.append({
					'value': value,
					'pid': pid,
					'author': pauthor
				})
				continue
			
			valid += 1
			authorsByValues[value] = {
				'key': THREAD_NAME,
				'pid': pid,
				'value': value,
				'author': pauthor,
				'created': datetime.fromtimestamp(pdate)
			}
		
		print('Comment proccessed:', len(comments))
		print('Valid comments:', valid)
		print('Bad comments:', bad)
		print('Duplicated comments:', len(duplicates))
		print('Deleted comments:', deleted)
	
		print('Saving....')
		for key, value in authorsByValues.items():
			if type(value) != dict: continue
			cur.execute('INSERT INTO `{}` VALUES(:pid,:value,:author,:created)'.format(THREAD_NAME), value)
		
		sql.commit()

def contrib():
	query = ('SELECT t1.value, t1.author,'
			' round(86400*(julianday(t1.time)-julianday(t2.time))) AS diff'
			' FROM {0} t1, {0} t2'
			' WHERE t2.value = t1.value - 1'
			' AND diff > 0').format(THREAD_NAME)
		
	if FILTER:
		query += ' AND ' + FILTER + '(t1.value)'
		
	cur.execute(query)
	print('Contributions in', THREAD_NAME)
		
	totals = {}
	table = cur.fetchall()

	if not table:
		print('Table', THREAD_NAME, 'is empty.')
		return
	
	for row in table:
		if row[1] in totals:
			totals[row[1]]['counts'] += 1
		else:
			totals[row[1]] = {'counts': 1, 'seconds': {}}
		
		s = int(row[2])
		if s == 3:
			# Filter <2000 users
			cur.execute(('SELECT author FROM stats_{} WHERE counts > 2000').format(THREAD_NAME))
			author = cur.fetchone()
				
			if author and row[1] == author:
				continue

		if s < 3:
			if s in totals[row[1]]['seconds']:
				totals[row[1]]['seconds'][s] += 1
			else:
				totals[row[1]]['seconds'][s] = 1
		
	new_dict = sorted(totals.items(), key=lambda x: x[1]['counts'], reverse=True)
		
	n = 1
	print('Rank|Username|Counts\n'
		'---|---|---')
	for k, v in new_dict:
		name = k
		value = v['counts']
		
		if v['seconds']:
			name += ' (' + ','.join([('{0} {1}s').format(v, k) for k, v in v['seconds'].items()]) + ')'
			
		print(n, '|', name, '|', value)
		n += 1
	
def dump():
	from operator import itemgetter
	query = 'SELECT * FROM `{0}`'.format(THREAD_NAME)
		
	if FILTER:
		query += (' WHERE {}(value)'.format(FILTER))
	
	query += ' ORDER BY value'
	cur.execute(query)
	
	filename = THREAD_NAME + '.txt'
	table = cur.fetchall()
		
	with open(filename, 'w') as file:
		for row in table:
			file.write(str(row) + '\n')

def clean():
	if FILTER:
		cur.execute('DELETE FROM `{0}` WHERE {1}(value)'.format(THREAD_NAME, FILTER))
	else:
		cur.execute('DELETE FROM `{0}`'.format(THREAD_NAME))
	sql.commit()
	print('Deleted all comments in', THREAD_NAME)

def stats():
	cur.execute('SELECT * FROM `stats_{}` ORDER BY counts DESC'.format(THREAD_NAME))
		
	table = cur.fetchall()
		
	with open('stats.md', 'w') as file:
		file.write('Rank|Username|Counts\n'
			'---|---|---\n')
			
		n = 1
		for row in table:
			file.write(' | '.join([str(n), row[0], str(row[1])]) + '\n')
			n += 1
			
		file.write('\nDate completed: {} UTC'.format(datetime.now()))
		
	print('Stats file written.')

def update_stats():
	if FILTER:
		cur.execute('SELECT * FROM `{0}` WHERE {1}(value)'.format(THREAD_NAME, FILTER))
	else:
		cur.execute('SELECT * FROM `{0}`'.format(THREAD_NAME))
	
	table = cur.fetchall()
	
	for row in table:
		author = row[2]

		cur.execute('SELECT * FROM stats_{} WHERE author=?'.format(THREAD_NAME), [author])
		result = cur.fetchone()

		if result:
			counts = result[1]
		else:
			cur.execute('INSERT INTO stats_{} VALUES(?, 0)'.format(THREAD_NAME), [author])
			counts = 0
		
		cur.execute('UPDATE stats_{} SET counts=? WHERE author=?'.format(THREAD_NAME), [counts + 1, author])
		sql.commit()

def main():
	parser = argparse.ArgumentParser(description='Process counting statistics.')
	
	parser.add_argument('-T', '--thread', help='select thread to crawl', action='store')
	parser.add_argument('-F', '--filter', help='set filter threads in database', action='store')
	parser.add_argument('-L', '--limit', help='limit 1000 counts starting from n.', action='store', type=int)
	
	parser.add_argument('-Cl', '--clean', help='clean threads in database.', action='store_true')
	parser.add_argument('-C', '--contrib', help='print contributions for threads in database.', action='store_true')
	parser.add_argument('-D', '--dump', help='dump all threads in database', action='store_true')
	
	parser.add_argument('-S', '--stats', help='display stats in database', action='store_true')
	parser.add_argument('-Su', '--stats-update', help='update stats in database', action='store_true')
	
	args = parser.parse_args()
	
	global THREAD_NAME, FILTER, LIMIT
	if args.thread:
		THREAD_NAME = args.thread
		THREAD = Thread(**THREAD_OPTIONS[THREAD_NAME])
	if args.filter:
		FILTER = args.filter
	if args.limit:
		start = args.limit
		final = args.limit + 1000
		
		# terrible hack i know
		FILTER = 'L'
		sql.create_function('L', 1, lambda n: start < int(n) < final)
	
	if args.clean:
		clean()
	elif args.contrib:
		contrib()
	elif args.dump:
		dump()
	
	elif args.stats:
		stats()
	elif args.stats_update:
		update_stats()

	else:
		replybot()

if __name__ == '__main__':
	main()