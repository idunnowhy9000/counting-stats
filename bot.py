import praw
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
	
	def __init__(self, name, options):
		self.name = name
		
		self.search = options['search'] if 'search' in options else False
		self.tid = options['tid'] if 'tid' in options else False
		self.exception = options['exception'] if 'exception' in options else []
		
		self.base = options['base'] if 'base' in options else 10
		self.group = options['group'] if 'group' in options else 0
		self.flags = options['flags'] if 'flags' in options else 0
		self.regex = re.compile((options['regex'] if 'regex' in options else BASE_REGEX), flags=self.flags)
		
		self.threads = []
		
		if 'parse' in options and callable(options['parse']):
			self.parse = lambda m: options['parse'](m)
		
		cur.execute('CREATE TABLE IF NOT EXISTS `{}`(id TEXT, value TEXT, parsed TEXT, author TEXT, time DATETIME, tid TEXT)'.format(name))
	
	def match(self, text):
		return self.regex.match(text)
	
	def parse(self, matches):
		value = re.sub(r'\W', '', matches.group(self.group))
		return int(value, self.base)
	
	def search_thread(self, r):
		threads = []
		if self.tid:
			if type(self.tid) == list:
				for id in self.tid:
					threads.append(r.get_submission(submission_id=id))
			else:
				threads.append(r.get_submission(submission_id=self.tid))
		else:
			for search in r.get_subreddit(SUBREDDIT).search(self.search, sort='new'):
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
		'tid': ['3je4es'],
		'parse': lambda matches: matches.group(0),
	},
	'sheep':{
		'search':'title:Sheep',
		'tid': ['3fzm7p']
	},
	'letters': {
		'search':'title:letters',
		'regex': '^\W*([A-Z]+)'
	},
	'updown': {
		'search':'((title:up down) OR (title:increment decrement) OR (title:tug of war)) NOT (title:2D)',
		'regex': r'^([^\d-]*\W*-?(\d+(\W*\d+)*|\d+))',
		'tid': ['3rwjeh', '3rstzg', '3rnxtp'],
		'parse': lambda matches: re.sub(r'[^\d-]', '', matches.group(0))
	},
	'palindrome': {
		'search':'title:palindrome NOT (title:hexadecimal OR title:hex OR title:binary)',
		'tid': ['3ujvpp'],
		'parse': lambda matches: matches.group(0)[(len(matches.group(0)) / 2):] if len(matches.group(0)) % 2 == 0 else matches.group(0)[floor(len(matches.group(0)) / 2):]
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
		'regex': r'^\W*(\d{1,2})\W*(\d{1,2})\W*(\d{1,2})\W*(AM|PM)?',
		'parse': lambda matches: matches.group(0) * 3600 + matches.group(1) * 60 + matches.group(2)
	},
	'binary': {
		'search': 'title:binary NOT (title:palindrome OR title:alphabet OR title:prime OR title:collatz)',
		'regex': r'^\W*([01,\.\s]+)',
		'tid': [
			'2bz9af',
			'2ayln3',
			'27v2uz',
			'23yj8b',
			'2114au',
			'1ynh3x',
			'1tsdch',
			'1qkila',
			'1n2o88',
			'1l05w8',
			'1jezs3',
			'1i1szs',
			'1g8kn3',
			'ziv8h',
			'uuz0l'
		],
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
		'search': 'title:12345',
		'regex': '^\W*((?:\D*1\D*2\D*3\D*4\D*5)(\D*=\W*(\d+(\W*\d+)*|\d+))?)',
		'exception': ['3vzjuy'],
		'parse': lambda matches: int(re.sub('\W', '', matches.group(3))) if matches.group(3) else matches.group(0)
	},
	'fourfours': {
		'regex': '^\W*((?:\D*4){4}(\D*=\W*(\d+(\W*\d+)*|\d+))?)',
		'tid': ['3109vi'],
		'parse': lambda matches: int(re.sub('\W', '', matches.group(3))) if matches.group(3).isdigit() else matches.group(0)
	},
	'gr8b8m8': {
		'regex':'^\W*(gr\W*\d+\W*b\W*\d+\W*m\W*\d+)',
		'tid': '3mwb6g',
		'group': 1,
		'flags': re.I
	}
}

# Filter database
FILTER = ''

print('Opening SQL Database')
sql = sqlite3.connect('sql.db', detect_types=sqlite3.PARSE_DECLTYPES)
sql.create_function('contains_69', 1, lambda n: '69' in n)
sql.create_function('ends_69', 1, lambda n: n[::2])

cur = sql.cursor()

def setup_thread(name):
	global thread
	if name in THREAD_OPTIONS:
		thread = Thread(name, THREAD_OPTIONS[name])
	else:
		print('Option for', name, 'does not exist.')
		exit()

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
	""" Bot """
	reddit = setup_reddit()
	posts = thread.search_thread(reddit)
	
	for post in posts:
		valid = skipped = deleted = duplicates = bad = 0
		authorsByValues = {}
		
		print(post)
	
		comments = post.comments
		for comment in comments:
			
			if isinstance(comment, praw.objects.MoreComments):
				comments.extend(comment.comments())
				continue
			
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
			
			cur.execute('SELECT 1 FROM `{}` WHERE ID=?'.format(thread.name), [pid])
			if cur.fetchone():
				# Post is already in the database
				continue
			
			matches = thread.match(pbody)
				
			if not matches:
				skipped += 1
				print('Skipped:', pbody.encode('utf8'))
				continue
			#value = pbody
			
			try:
				value = thread.parse(matches)
			except ValueError as e:
				bad += 1
				print(e)
				continue
			
			cur.execute('SELECT 1 FROM `{}` WHERE value=?'.format(thread.name), [value])
			if (value in authorsByValues) or cur.fetchone():
				duplicates += 1
				continue
			
			valid += 1
			authorsByValues[value] = {
				'tid': post.id,
				'pid': pid,
				'body': pbody,
				'value': value,
				'author': pauthor,
				'created': datetime.fromtimestamp(pdate),
			}
		
		print('Comment proccessed:', len(comments))
		print('Valid comments:', valid)
		print('Bad comments:', bad)
		print('Duplicated comments:', duplicates)
		print('Deleted comments:', deleted)
	
		print('Saving....')
		for key, value in authorsByValues.items():
			cur.execute('INSERT INTO `{}` VALUES(:pid,:body,:value,:author,:created,:tid)'.format(thread.name), value)
		
		sql.commit()

def contrib():
	""" Dump thread's contribution """
	from collections import Counter, defaultdict
	
	query = ('SELECT t1.parsed, t1.author,'
			' round(86400*(julianday(t1.time)-julianday(t2.time))) AS diff'
			' FROM `{0}` t1, `{0}` t2'
			' WHERE t2.parsed = t1.parsed - 1'
			' AND diff > 0').format(thread.name)
		
	if FILTER:
		query += ' AND ' + FILTER + '(t1.value)'
		
	cur.execute(query)
	print('Contributions in', thread.name)
		
	table = cur.fetchall()
	counts = Counter()
	seconds = defaultdict(Counter)

	if not table:
		print('Table', thread.name, 'is empty.')
		return
	
	for row in table:
		author = row[1]
		counts[author] += 1
		
		s = int(row[2])
		if s == 3:
			# Filter <2000 users
			cur.execute(('SELECT 1 FROM `stats_{}` WHERE counts > 2000 AND author=?').format(thread.name), author)
			result = cur.fetchone()
				
			if result:
				continue

		if s < 3:
			seconds[author][s] += 1

	n = 1
	print('Rank|Username|Counts\n'
		'---|---|---')
	for count in counts.most_common():
		name = count[0]
		value = count[1]
		
		if name in seconds:
			name += ' (' + ','.join([('{0} {1}s').format(v, k) for k, v in seconds[name].items()]) + ')'
			
		print(n, '|', name, '|', value)
		n += 1
	
def dump():
	""" Dump thread """
	query = 'SELECT * FROM `{0}`'.format(thread.name)
		
	if FILTER:
		query += (' WHERE {}(value)'.format(FILTER))
	
	query += ' ORDER BY value'
	cur.execute(query)
	
	filename = thread.name + '.txt'
	table = cur.fetchall()
		
	with open(filename, 'w', encoding='utf-8') as file:
		for row in table:
			file.write(str(row) + '\n')
	
	print('File', filename, 'written')

def clean():
	""" Delete database files """
	if input('Are you really sure to clean database?').lower() == 'y':
		return
	
	if FILTER:
		cur.execute('DELETE FROM `{0}` WHERE {1}(value)'.format(thread.name, FILTER))
	else:
		cur.execute('DELETE FROM `{}`'.format(thread.name))
	sql.commit()
	print('Deleted all comments in', thread.name)

def stats():
	""" Writes statistics to a file """
	cur.execute('SELECT * FROM `stats_{}` ORDER BY counts DESC'.format(thread.name))
		
	table = cur.fetchall()
		
	with open('stats_{}.txt'.format(thread.name), 'w') as file:
		file.write('Rank|Username|Counts\n'
			'---|---|---\n')
			
		n = 1
		for row in table:
			file.write(' | '.join([str(n), row[0], str(row[1])]) + '\n')
			n += 1
			
		file.write('\nDate completed: {} UTC'.format(datetime.now()))
		
	print('Stats file written.')

def update_stats():
	""" Updates stat database for thread """
	cur.execute('CREATE TABLE IF NOT EXISTS `stats_{}`(author TEXT, counts INT)'.format(thread.name))
	
	if FILTER:
		cur.execute('SELECT author FROM `{0}` WHERE {1}(value)'.format(thread.name, FILTER))
	else:
		cur.execute('SELECT author FROM `{}`'.format(thread.name))
	
	table = cur.fetchall()
	
	for row in table:
		author = row[0]

		cur.execute('SELECT counts FROM `stats_{}` WHERE author=?'.format(thread.name), [author])
		result = cur.fetchone()

		if result:
			counts = result[0]
		else:
			cur.execute('INSERT INTO `stats_{}` VALUES(?, 0)'.format(thread.name), [author])
			counts = 0
		
		cur.execute('UPDATE `stats_{}` SET counts=? WHERE author=?'.format(thread.name), [counts + 1, author])
	
	sql.commit()

def convert_asa(file):
	""" Converts from anothershittyalt's format to my format """
	import csv
	
	deleted = 0
	
	with open(file, 'r') as csvfile:
		reader = csv.reader(csvfile)
		
		next(reader, None) # skip the headers
		for row in reader:
			value = row[0]
			parsed = int(row[1])
			author = row[2]
			time = datetime.fromtimestamp(int(row[3]))
			pid = row[4]
			tid = row[5]
			
			if author == '[deleted]':
				deleted += 1
			
			cur.execute('INSERT INTO `{}` VALUES(?,?,?,?,?,?)'.format(thread.name), [pid, value, parsed, author, time, tid])
		
		sql.commit()
	
	print('Converted successfully.')
	print('Deleted comments:', deleted)

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
	
	parser.add_argument('-Ca', '--convert-asa', help="converts anothershittyalt's format to this format", action='store')
	
	args = parser.parse_args()
	
	if args.thread:
		setup_thread(args.thread)
	else:
		setup_thread(THREAD_NAME)
	
	global FILTER
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

	elif args.convert_asa:
		convert_asa(args.convert_asa)
	
	else:
		replybot()

if __name__ == '__main__':
	main()