#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__license__ = "GPL"
__version__ = "1.0.1"

from selenium import webdriver
from bs4 import BeautifulSoup
from datetime import date
import datetime
import time
import os
import json
from functools import reduce
import logging
import yara
import hashlib
from frameworks.database import DataBase


class RedditCrawler:
	def __init__(
		self,
		dir_webdriver=None,
		headless=None,
		database_name=None,
		database_path=None,
		time_scroll=None,
		sleep_time=None,
		save_log_dir=None,
		dic=None,
		rule_path=None
		):

		if dir_webdriver is not None:

			self.logger = logging.getLogger('Start:Twitter')
			self.logger.debug('Capturing configuration file information.')
			self.today = date.today()
			self.dir_webdriver = dir_webdriver
			self.rule_path = rule_path
			self.database_name = database_name
			self.database_path = database_path
			self.time_scroll = time_scroll
			self.sleep_time = sleep_time
			self.save_log_dir = save_log_dir
			self.dic = dic
			options = webdriver.FirefoxOptions()

			if headless:
				options.add_argument("-headless")
				self.logger.info('Headless is enabled, the browser will not open and everything will work in the background.')
			else:
				self.logger.info('Headless is disabled, the browser will open.')

			self.logger.debug('Setting additional browser information.')
			_browser_profile = webdriver.FirefoxProfile()
			self.logger.debug('Disabling browser notifications.')
			_browser_profile.set_preference("general.useragent.override", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:63.0) Gecko/20100101 Firefox/63.0")
			_browser_profile.set_preference("dom.webnotifications.enabled", False)
			self.logger.debug('Gathering the information and creating the webdriver.')

			self.driver = webdriver.Firefox(
				executable_path=self.dir_webdriver,
				options=options,
				firefox_profile=_browser_profile)
			self.database = DataBase(database_path=self.database_path,
				database_name=self.database_name,)

	@property
	def start(self):
		self.pages()
		self.driver.close()

	def pages(self):
		self.logger.info('Getting page dictionary.')
		self.logger.info('Starting Crawler. Please wait ... This process may take a long time.\n')

		for dicionario in self.dic:
			pages = dicionario['group']['name']
			urls = dicionario['group']['id']

			self.logger.info('Crawling in {}.'.format(pages))
			self.logger.debug('Waiting for runtime to avoid bottleneck.')
			time.sleep(self.sleep_time)

			self.logger.info('Getting group feed ...')

			soup = BeautifulSoup(self.scroll(url=urls), "html.parser")
			self.logger.info('The entire feed has already been obtained, starting the scraping process.')

			self.crawler_raw(raw=soup, page=pages)

	def crawler_raw(self,raw=None, page=None):
		if raw is not None:
			for posts in raw.findAll('div', {'class':'scrollerItem'}):
				user_post = "Null"
				user_post_profile = "Null"
				user_post_post = "Null"
				user_post_urls = "Null"
				yararule = "Null"
				md5 = "Null"
				sha256 = "Null"
				score = 0

				try:
					user_post_post = self.replaces_text(raw=posts.find('div',{'class':'RichTextJSON-root'}).get_text())
				except (AttributeError) as e:
					user_post_post = self.replaces_text(raw=posts.find('h3',{'class':'_eYtD2XCVieq6emjKBH3m'}).get_text())
				try:
					user_post = posts.find('a', {'class':'oQctV4n0yUb0uiHDdGnmE'}).get_text()
				except (AttributeError) as e:
					user_post = "Not Found"

				if "Not Found" in user_post:
					user_post_profile = "Not Found"
				else:
					user_post_profile = "https://www.reddit.com/user/{user}/".format(
						user=posts.find('a', {'class':'oQctV4n0yUb0uiHDdGnmE'}).get_text().replace('u/', ''))

				try:
					if posts.find('a', {'class':'_3t5uN8xUmg0TOwRCOGQEcU'})['href'] is not None:
						user_post_urls = posts.find('a', {'class':'_3t5uN8xUmg0TOwRCOGQEcU'})['href']
					else:
						user_post_urls = "Null"
				except (TypeError) as e:
					 user_post_urls = "Null"


				encoded_paste_data = user_post_post.encode('utf-8')
				md5 = hashlib.md5(encoded_paste_data).hexdigest()
				sha256 = hashlib.sha256(encoded_paste_data).hexdigest()

				check_rule = self.check_yrarule(raw=self.replaces_text(raw=user_post_post))

				if len(check_rule) == 0:
					yararule = "no_match"
					full_match = "no_match"
					score = 0
				else:
					cont = 1
					yararule = check_rule[0]
					while cont <= int(len(check_rule)):
						score += int(check_rule[cont-1].meta['score'])
						full_match = check_rule
						cont +=1

				infos = {
					"tag": "Reddit",
					"page_name": "{}".format(page),
					"adm_user": "Null",
					"adm_profile": "Null",
					"user_post_name": "{}".format(user_post),
					"user_post_profile": "{}".format(user_post_profile),
					"user_post_post": "{}".format(user_post_post),
					"user_post_url": "{}".format(user_post_urls),
					"yararule": "{}".format(yararule),
					"full_match": "{}".format(full_match),
					"MD5": "{}".format(md5),
					"SHA256": "{}".format(sha256),
					"mydate": "{}".format(self.today),
					"score": "{}".format(score)
				}

				savedatabase = self.database.save_db(tag="Reddit",
					group_url=self.replaces_text(raw=user_post_urls),
					title=user_post_profile,
					post=user_post_post,
					user_post=user_post,
					database_path=self.database_path,
					database_name=self.database_name,)

				if savedatabase:
					logs_save_splunk = '{0}/reddit-{1}.json'.format(self.save_log_dir, datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))

					if not os.path.exists(logs_save_splunk):
						 arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
						 arquivo.close()

					arquivo = open(logs_save_splunk, 'r', encoding="utf-8")
					conteudo = arquivo.readlines()
					conteudo.append(json.dumps(infos, ensure_ascii=False)+'\n')
					arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
					arquivo.writelines(conteudo)
					arquivo.close()


	"""
		Remove line breaks and other characters, which may compromise the final file.
	"""
	def replaces_text(self, raw=None):
		if raw is not None:
			repls = (
				('\n', r' '),
				('\r', r' '),
				('\t', r' '),
				('\s', r' '),
				('"', r' '),
				("'", r' '),
				("(", r" "),
				(")", r" "),
				("\xa0", r" "),
				("`", " "),
				("’", " ")
			)
			data = reduce(lambda a, kv: a.replace(*kv), repls, raw)
			return data

	"""
		Category search through configured yaratules
	"""

	def check_yrarule(self, raw=None):
		if raw is not None:
			index_file = os.path.join(self.rule_path, 'index.yar')
			rules = yara.compile(index_file)
			matches = rules.match(data=raw)

			return matches


	def scroll(self, url=None):
		if url is not None:
			try:
				self.driver.get("https://www.reddit.com/r/{url}/new/".format(url=url))

				SCROLL_PAUSE_TIME = self.time_scroll

				last_height = self.driver.execute_script("return document.body.scrollHeight")

				while True:
					self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")

					time.sleep(SCROLL_PAUSE_TIME)

					new_height = self.driver.execute_script("return document.body.scrollHeight")
					if new_height == last_height:
						break
					last_height = new_height

				time.sleep(self.sleep_time)
				return self.driver.page_source
			except:
				pass
