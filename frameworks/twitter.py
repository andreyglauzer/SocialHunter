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


class TwitterCrawler:
	def __init__(
		self,
		dir_webdriver=None,
		user=None,
		passwd=None,
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
			self.user = user
			self.passwd = passwd
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
		self.logger.info('Logging in to Twitter.')
		self.login()
		self.logger.info('Login successfully.')
		self.logger.info('Starting Crawler.')
		self.groups()
		self.driver.close()

	def login(self):
		self.driver.get("https://twitter.com/login")
		self.logger.debug('Applying user.')
		self.driver.find_element_by_css_selector('input.js-username-field').send_keys(self.user)
		self.logger.debug('Waiting ... To apply the password.')
		time.sleep(5)
		self.logger.debug('Applying the password.')
		self.driver.find_element_by_css_selector('input.js-password-field').send_keys(self.passwd)
		self.logger.debug('Submit at login.')
		self.driver.find_element_by_xpath('/html/body/div[1]/div[2]/div/div/div[1]/form/div[2]/button').click()


	def scroll(self, url=None):
		if url is not None:
			self.driver.get(url)

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

	"""
		Remove line breaks and other characters that may compromise the final file.
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

	def check_yrarule(self, raw=None):
		if raw is not None:
			index_file = os.path.join(self.rule_path, 'index.yar')
			rules = yara.compile(index_file)
			matches = rules.match(data=raw)

			return matches

	def groups(self, urls_posts=None):
		self.logger.info('Getting page dictionary.')
		self.logger.info('Starting Crawler. Wait ... This process can be time consuming.\n')

		for dicionario in self.dic:
			pages = dicionario['group']['name']
			urls = dicionario['group']['id']

			self.logger.info('Crawling on {}.'.format(pages))
			self.logger.debug('Waiting for runtime to avoid bottleneck.')
			time.sleep(self.sleep_time)
			self.logger.debug('Entering the crawler page.')
			self.driver.get(urls)
			self.logger.debug('Setting Scroll Time.')

			self.logger.debug('Getting the page scroll.')
			last_height = self.driver.execute_script("return document.body.scrollHeight")

			self.logger.info('Starting Crawler process of the entire Feed.')

			soup = BeautifulSoup(self.scroll(url=urls), "html.parser")
			self.logger.info('The entire feed has already been obtained, starting the scraping process.')

			for raw in soup.find('section', {'role':'region'}).findAll('article', {'role':'article'}):
				user_post =  "Null"
				user_post_url =  "Null"
				user_post_post =  "Null"

				user_post = raw.find('div', {'dir':'ltr'}).get_text().replace('@','')

				lang = ['aa','ab','af','ak','alb','am','ar','an','arm','as','av','ae','ay','az','ba','bm','baq','be','bn','bh','bi','tib','bs','br','bg','bur','ca','cze','ch','ce','chi','cu','cv','kw','co','cr','wel','cze','da','ger','dv','dut','dz','gre','en','eo','et','baq','ee','fo','per','fj','fi','fre','fre','fy','ff','geo','ger','gd','ga','gl','gv','gre','gn','gu','ht','ha','he','hz','hi','ho','hr','hu','arm','ig','ice','io','ii','iu','ie','ia','id','ik','ice','it','jv','ja','kl','kn','ks','geo','kr','kk','km','ki','rw','ky','kv','kg','ko','kj','ku','lo','la','lv','li','ln','lt','lb','lu','lg','mac','mh','ml','mao','mr','may','mac','mg','mt','mn','mao','may','bur','na','nv','nr','nd','ng','ne','dut','nn','nb','no','ny','oc','oj','or','om','os','pa','per','pi','pl','pt','ps','tz','qu','rm','rum','rum','rn','ru','sg','sa','si','slo','slo','sl','se','sm','sn','sd','so','st','es','alb','sc','sr','ss','su','sw','sv','ty','ta','tt','te','tg','tl','th','tib','ti','to','tn','ts','tk','tr','tw','ug','uk','ur','uz','ve','vi','vo','wel','wa','wo','xh','yi','yo','za','chi','zu']

				for post_lang in lang:
					try:
						user_post_post = self.replaces_text(raw=raw.find('div', {'lang':post_lang}).get_text())
						for urls_posts in raw.find('div', {'lang':post_lang}).findAll('a'):
							user_post_url = urls_posts['title']
						break
					except:
						user_post_post = "Null"

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

				if user_post_post == "Null":
					self.logger.debug('Empty post will not be saved.')
				else:

					infos = {
						"tag": "Twitter",
						"page_name": "{}".format(pages),
						"adm_user": "Null",
						"adm_profile": "Null",
						"user_post_name": "{}".format(user_post),
						"user_post_profile": "https://twitter.com/{}".format(user_post),
						"user_post_post": "{}".format(user_post_post),
						"user_post_url": "{}".format(user_post_url),
						"yararule": "{}".format(yararule),
						"full_match": "{}".format(full_match),
						"MD5": "{}".format(md5),
						"SHA256": "{}".format(sha256),
						"mydate": "{}".format(self.today),
						"score": "{}".format(score)
					}

					savedatabase = self.database.save_db(tag="Twitter",
						group_url=self.replaces_text(raw=user_post_url),
						title="https://twitter.com/{}".format(user_post),
						post=self.replaces_text(raw=user_post),
						user_post=self.replaces_text(raw=user_post),
						database_path=self.database_path,
						database_name=self.database_name,)


					if savedatabase:
						logs_save_splunk = '{0}/twitter-{1}.json'.format(self.save_log_dir, datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))

						if not os.path.exists(logs_save_splunk):
							 arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
							 arquivo.close()

						arquivo = open(logs_save_splunk, 'r', encoding="utf-8")
						conteudo = arquivo.readlines()
						conteudo.append(json.dumps(infos, ensure_ascii=False)+'\n')
						arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
						arquivo.writelines(conteudo)
						arquivo.close()
