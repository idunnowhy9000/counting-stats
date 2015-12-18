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
THREAD_NAMES = ['main']
# Base regex for base 10 threads
BASE_REGEX = r'^\W*(\d+(\W*\d+)*|\d+)'
# Thread options
THREAD_OPTIONS = {
	'main': {
		'search': 'title:Counting Thread',
		'regex': BASE_REGEX,
		'tid': ['3x85wy']
	},
	'alphanumeric': {
		'search': 'title:Alphanumerics',
		'regex': '^\W*([0-9A-Z]+)'
	},
	'sheep':{
		'search':'title:Sheep',
		'regex': BASE_REGEX,
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
		'regex': BASE_REGEX,
		'tid': ['3ujvpp']
	},
	'hexadecimal': {
		'search':'(title:hexadecimal OR title:hex) NOT title:palindrome',
		'regex': r'^\W*(?:0[xX])?([0-9a-fA-F]+)'
	},
	'palindrome-hex': {
		'search':'title:hexadecimal palindrome OR title:hex palindrome',
		'regex': r'^\W*(?:0[xX])?([0-9a-fA-F]+)'
	},
	'time': {
		'search':'title:time counting thread',
		'regex': r'^\W*(\d{1,2})\W*(\d{1,2})\W*(\d{1,2})\W*(AM|PM)?'
	},
	'binary': {
		'search': 'title:binary NOT title:palindrome',
		'regex': r'^\W*([01,\.\s]+)'
	},
	'ternary': {
		'search': 'title:ternary counting thread',
		'regex': r'^\W*([012,\.\s]+)'
	},
	'roman': {
		'tid': '3smutv',
		'regex': '^[~`#*_\\s\\[>~]*([\u2182\u2181MDCLXVI\\W]+)'
	},
	'12345': {
		'regex': '^(\D*1\D*2\D*3\D*4\D*5\D*)(=\W*\d+(\W*\d+)*|\d+)?',
	},
	'fourfours': {
		'regex': '^(\D*4){4}\D*=\W*(\d+(\W*\d+)*|\d+)',
	},
	'gr8b8m8': {
		'regex':'^\W*(gr\W*\d+\W*b\W*\d+\W*m\W*\d+)',
		'tid': '3mwb6g',
		'flags': re.I
	},
	
	'text': {
		'regex': '^\W*(?:\d+(?:\W*\d+\W*)*|\d+)?([^\d](?:.|\n)*)$',
	}
}
# Parser maker
def make_parser(group=0, base=None):
	if type(base) == int:
		return lambda matches: int(re.sub(r'\W', '', matches.group(group)), base)
	return lambda matches: re.sub(r'\W', '', matches.group(group))

# Number parser for side threads
def PARSER_palindrome(matches):
	str = re.sub(r'\W', '', matches.group(0))
	if str != str[::-1]:
		print('Warning:', str, 'is not a palindrome')
	return str

THREAD_OPTIONS['palindrome']['parser'] = PARSER_palindrome

def PARSER_phexadecimal(matches):
	str = re.sub(r'\W', '', matches.group(0))
	if str != str[::-1]:
		print('Warning:', str, 'is not a palindrome')
	return str
THREAD_OPTIONS['palindrome-hex']['parser'] = PARSER_phexadecimal

def PARSER_time(matches):
	hour = int(re.sub(r'\W', '', matches.group(1)))
	minute = int(re.sub(r'\W', '', matches.group(2)))
	seconds = int(re.sub(r'\W', '', matches.group(3)))
	return hour * 60 + minute * 60 + seconds

THREAD_OPTIONS['time']['parser'] = PARSER_time

THREAD_OPTIONS['gr8b8m8']['parser'] = make_parser()
THREAD_OPTIONS['12345']['parser'] = make_parser(1, 10)
THREAD_OPTIONS['fourfours']['parser'] = make_parser(1, 10)
THREAD_OPTIONS['text']['parser'] = make_parser()
THREAD_OPTIONS['hexadecimal']['parser'] = make_parser(0, 16)
THREAD_OPTIONS['alphanumeric']['parser'] = make_parser()
THREAD_OPTIONS['binary']['parser'] = make_parser(0, 2)
THREAD_OPTIONS['ternary']['parser'] = make_parser(0, 3)

# Compile the regexes
for key in THREAD_NAMES:
	option = THREAD_OPTIONS[key]
	flags = option['flags'] if 'flags' in option else 0
	THREAD_OPTIONS[key]['compiled_regex'] = re.compile(THREAD_OPTIONS[key]['regex'], flags=flags)

# Limit
LIMIT = None

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

for key in THREAD_NAMES:
	cur.execute('CREATE TABLE IF NOT EXISTS {}(id TEXT, value TEXT, author TEXT, time DATETIME)'.format(key))
	cur.execute('CREATE TABLE IF NOT EXISTS stats_{}(author TEXT, counts INT)'.format(key))

def replybot():
	
	# Good to go
	r = praw.Reddit(USERAGENT)

	try:
		import login
		r.login(login.USERNAME, login.PASSWORD)
	except ImportError:
		pass

	subreddit = r.get_subreddit(SUBREDDIT)

	threads = []
	for key in THREAD_NAMES:
		base = THREAD_OPTIONS[key]
		submission = None
		submissions = []
		
		if 'tid' in base:
			if type(base['tid']) == list:
				for id in base['tid']:
					submissions.append({
						'thread': r.get_submission(submission_id=id),
						'type': key
					})
			else:
				submission = r.get_submission(submission_id=base['tid'])
		else:
			do = 'except' in base
			for search in subreddit.search(base['search'], sort='new'):
				tid = search.id
				if do and tid in base['except']:
					continue
				
				submissions.append({
					'thread': search,
					'type': key
				})
		
		if submission:
			threads.append({
				'thread': submission,
				'type': key
			})
		elif submissions:
			threads.extend(submissions)

	print(threads)
	
	for thread in threads:
		_max = -inf
		_min = inf
		
		valid = bad = skipped = deleted = 0
		authorsByValues = missing = {}
		duplicates = []
		
		key = thread['type']
		option = THREAD_OPTIONS[key]
		
		post = thread['thread']
		comments = post.comments
		
		print(post)
		
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
			
			cur.execute('SELECT * FROM `{}` WHERE ID=?'.format(key), [pid])
			if cur.fetchone():
				# Post is already in the database
				continue
			
			matches = option['compiled_regex'].match(pbody)
				
			if not matches:
				skipped += 1
				print('Skipped:', pbody.encode('utf8'))
				continue
			
			try:
				if 'parser' in option:
					val = option['parser'](matches)
				else:
					val = int(re.sub(r'\W', '', matches.group(0)))
			except ValueError as e:
				bad += 1
				print(e)
				continue
			
			cur.execute('SELECT * FROM `{}` WHERE value=?'.format(key), [val])
			if (val in authorsByValues) or cur.fetchone():
				duplicates.append({
					'value': val,
					'pid': pid,
					'author': pauthor
				})
				continue
			
			valid += 1
			authorsByValues[val] = {
				'key': key,
				'pid': pid,
				'value': val,
				'author': pauthor,
				'created': datetime.fromtimestamp(pdate)
			}
		
		print('Comment proccessed:', len(comments))
		print('Valid comments:', valid)
		print('Bad comments:', bad)
		print('Missing comments:', len(missing))
		print('Duplicated comments:', len(duplicates))
		print('Deleted comments:', deleted)
	
		print('Saving....')
		for key, value in authorsByValues.items():
			if type(value) != dict: continue
			cur.execute('INSERT INTO `{}` VALUES(:pid,:value,:author,:created)'.format(value))
		
		sql.commit()

def contrib():
	for name in THREAD_NAMES:
		query = ('SELECT t1.value, t1.author, round(86400*(julianday(t1.time)-julianday(t2.time))) AS diff'
				' FROM {0} t1, {0} t2'
				' WHERE t2.value = t1.value - 1'
				' AND diff > 0').format(name)
		
		if FILTER:
			query += ' AND ' + FILTER + '(t1.value)'
		
		cur.execute(query)
		print('Contributions in', name)
		
		totals = {}
		table = cur.fetchall()
		
		if not table:
			print('Table', name, 'is empty.')
			continue
		
		for row in table:
			if row[1] in totals:
				totals[row[1]]['counts'] += 1
			else:
				totals[row[1]] = {'counts': 1, 'seconds': {}}
			
			s = int(row[2])
			if s == 3:
				# Filter <2000 users
				cur.execute(('SELECT author FROM stats_{} WHERE counts > 2000').format(name))
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
	for name in THREAD_NAMES:
		if FILTER:
			cur.execute('SELECT * FROM `{0}` WHERE {1}(value)'.format(name, FILTER))
		else:
			cur.execute('SELECT * FROM `{}`'.format(name))
		
		fn = name + '.txt'
		table = cur.fetchall()
		
		with open(fn, 'w') as file:
			for row in table:
				file.write(str(row) + '\n')

def clean():
	for name in THREAD_NAMES:
		if FILTER:
			cur.execute('SELECT * FROM `{0}` WHERE {1}(value)'.format(name, FILTER))
		else:
			cur.execute('SELECT * FROM `{0}`'.format(name))

		print('Deleted all comments in', name)

def stats():
	for name in THREAD_NAMES:
		if FILTER:
			cur.execute('SELECT * FROM `stats_{0}` WHERE {1}(value)'.format(name, FILTER))
		else:
			cur.execute('SELECT * FROM `stats_{}`'.format(name))
		
		table = cur.fetchall()
		new_table = sorted(table, key=lambda n: n[1], reverse=True)
		
		with open('stats.txt', 'w') as file:
			file.write('Rank|Username|Counts\n'
				'---|---|---\n')
			
			n = 1
			for row in new_table:
				file.write(' | '.join([str(n), row[0], str(row[1])]) + '\n')
				n += 1
			
		print('Stats file written.')

def update_stats():
	for name in THREAD_NAMES:
		if FILTER:
			cur.execute('SELECT * FROM `{0}` WHERE {1}(value)'.format(name, FILTER))
		else:
			cur.execute('SELECT * FROM `{0}`'.format(name))
		
		table = cur.fetchall()
		
		for row in table:
			author = row[2]

			cur.execute('SELECT * FROM stats_{} WHERE author=?'.format(name), [author])
			result = cur.fetchone()

			if result:
				counts = result[1]
			else:
				cur.execute('INSERT INTO stats_{} VALUES(?, 0)'.format(name), [author])
				counts = 0
				
			print('Updating', author)
			cur.execute('UPDATE stats_{} SET counts=? WHERE author=?'.format(name), [counts + 1, author])
		
		sql.commit()

def main():
	parser = argparse.ArgumentParser(description='Process counting statistics.')
	
	parser.add_argument('-T', '--threads', help='add or remove threads to track', action='append')
	parser.add_argument('-F', '--filter', help='set filter threads in database', action='store')
	parser.add_argument('-L', '--limit', help='limit 1000 counts starting from n.', action='store', type=int)
	
	parser.add_argument('-Cl', '--clean', help='clean threads in database.', action='store_true')
	parser.add_argument('-C', '--contrib', help='print contributions for threads in database.', action='store_true')
	parser.add_argument('-D', '--dump', help='dump all threads in database', action='store_true')
	
	parser.add_argument('-S', '--stats', help='display stats in database', action='store_true')
	parser.add_argument('-Su', '--stats-update', help='update stats in database', action='store_true')
	
	args = parser.parse_args()
	
	global THREAD_NAMES, FILTER, LIMIT
	if args.threads:
		THREAD_NAMES = args.threads
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