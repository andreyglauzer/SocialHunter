#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__license__ = "GPL"
__version__ = "1.0.1"

import sqlite3
import os

class DataBase:
	def __init__(self,
		database_path=None,
		database_name=None,
		):
		self.database_path = database_path
		self.database_name = database_name
		if not os.path.exists('{path}/{filename}'.format(path=self.database_path, filename=self.database_name)):
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS SOCIAL ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'tag TEXT, group_url TEXT, title TEXT, post TEXT, user_post TEXT);')


			conn.commit()
			conn.close()
		else:
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS SOCIAL ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'tag TEXT, group_url TEXT, title TEXT, post TEXT, user_post TEXT);')

			conn.commit()
			conn.close()


	def save_db(
		self,
		tag=None,
		group_url=None,
		title=None,
		post=None,
		user_post=None,
		database_path=None,
		database_name=None,):

		if tag is not None:
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()
			r = cursor.execute("SELECT * FROM SOCIAL WHERE tag='{tag}' AND title='{title}' AND post='{post}' AND user_post='{user_post}' AND group_url='{group_url}';".format(tag=tag,
						title=title,
						post=post,
						user_post=user_post,
						group_url=group_url))


			if r.fetchall():
				save_file = False
			else:
				save_file = True
				conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
				cursor = conn.cursor()
				cursor.execute("""
				INSERT INTO SOCIAL (tag,title,post,user_post,group_url)
				VALUES ('%s', '%s', '%s', '%s', '%s')
				""" % (tag,title,post,user_post,group_url))
				conn.commit()
				conn.close()

			return save_file
