#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__license__ = "GPL"
__version__ = "1.0.1"

from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from bs4 import BeautifulSoup
from datetime import date
import datetime
import time
import sys
import os
import io
from functools import reduce
import yara
import hashlib
import json
import logging
from frameworks.database import DataBase

class FacebookCrawler:
	def __init__(self,
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

			self.logger = logging.getLogger('Start:Facebook')
			self.logger.debug('Capturing configuration file information.')
			self.today = date.today()
			self.dir_webdriver = dir_webdriver
			self.user = user
			self.passwd = passwd
			self.dic = dic
			self.rule_path = rule_path
			self.database_name = database_name
			self.database_path = database_path
			self.time_scroll = time_scroll
			self.sleep_time = sleep_time
			self.save_log_dir = save_log_dir
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
		self.logger.info('Logging in to Facebook.')
		self.login()
		self.logger.info('Login successfully.')
		self.logger.info('Starting Crawler.')
		self.groups()

	def login(self):

		self.driver.get("https://facebook.com")
		self.logger.debug('Applying user.')
		self.logger.debug('Waiting ... To apply the password.')
		self.driver.find_element_by_id("email").send_keys(self.user)
		self.logger.debug('Applying the password.')
		self.driver.find_element_by_id("pass").send_keys(self.passwd)
		self.logger.debug('Submit at login.')
		self.driver.find_element_by_id("loginbutton").click()


	def check_yrarule(self, raw=None):
		if raw is not None:
			index_file = os.path.join(self.rule_path, 'index.yar')
			rules = yara.compile(index_file)
			matches = rules.match(data=raw)

			return matches

	def scroll(self, url=None):
		if url is not None:
			self.driver.get("{url}?sorting_setting=RECENT_ACTIVITY".format(url=url))

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


	def groups(self, urls_posts=None):
		self.logger.info('Getting page dictionary.')
		self.logger.info('Starting Crawler. Wait ... This process can be time consuming.\n')
		for dicionario in self.dic:
			pages = dicionario['group']['name']
			urls = "https://www.facebook.com/groups/{uid}/".format(uid=dicionario['group']['id'])

			self.logger.info('Crawling in {}.'.format(pages))
			self.logger.info('Getting the admins from the facebook page.')

			self.driver.get("{url}admins/".format(url=urls))
			soup = BeautifulSoup(self.driver.page_source, "html.parser")
			info_adm = self.adm(raw=soup)

			self.logger.info('The group administrator is {}'.format(info_adm[0]))
			time.sleep(self.sleep_time)

			self.logger.info('Getting group feed ...')


			soup = BeautifulSoup(self.scroll(url=urls), "html.parser")
			self.post(
				raw=soup,
				adm_user=info_adm[0],
				adm_profile=info_adm[1],
				page_name=pages)


		self.driver.close()

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

	"""
		Returns only the first page admin,
		Because the order may change according to facebook,
		and the page may have more than one administrator.
	"""
	def adm(self, raw=None):
		if raw is not None:
			for adm_user in raw.find("div", {"class":"uiProfileBlockContent _61ce"}):
				name = adm_user.find('a').get_text()
				profile = adm_user.find('a')['href'].split('?')[0]
				return name, profile

	"""
		Get all information from the posts, which was possible to get the feed according to the scroll time that was set in the settings file.
	"""
	def post(self,
		raw=None,
		adm_user=None,
		adm_profile=None,
		page_name=None,):
		self.logger.debug('Getting the page posts.')
		if raw is not None:
			for posts in raw.find('div', {'id':'pagelet_group_mall'}).findAll('div', {'class':'userContentWrapper'}):

				user_post_name = "Null"
				user_post_profile = "Null"
				user_post_post = "Null"
				user_post_url = "Null"
				yararule = "Null"
				md5 = "Null"
				sha256 = "Null"
				score = 0

				user_post_name = posts.find('span',{'class':'fwb'}).get_text()
				user_post_profile = posts.find('span',{'class':'fwb'}).find('a')['href'] \
					.split('fref')[0] \
					.replace('&', '') \
					.replace('?', '')
				user_post_post =  posts.find('div', {'class':'userContent'}) \
					.get_text() \
					.replace('Ver mais', '') \
					.replace('Ver Tradução', '')

				try:
					user_post_url = posts.find('div', {'class':'userContent'}).findAll('a')[0].get_text()
					if 'Ver mais' in user_post_url:
						user_post_url =  "Null"
				except (AttributeError, IndexError) as e:
					try:
						user_post_url = posts.find('div',{'class':'_6ks'}).findAll('a')[0]['href']
					except (AttributeError, IndexError) as e:
						user_post_url = "Null"

				if user_post_post:
					pass
				else:
					try:
						user_post_post = "Usuário compartilhou link: {}".format(posts.find('div',{'class':'_6ks'}).findAll('a')[0]['href'])
						user_post_url = posts.find('div',{'class':'_6ks'}).findAll('a')[0]['href']
					except (AttributeError) as e:
						pass

				if user_post_post:
					encoded_paste_data = self.replaces_text(raw=user_post_post).encode('utf-8')
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
						"tag": "Facebook",
						"page_name": "{}".format(page_name),
						"adm_user": "{}".format(adm_user),
						"adm_profile": "{}".format(adm_profile),
						"user_post_name": "{}".format(user_post_name),
						"user_post_profile": "{}".format(user_post_profile),
						"user_post_post": "{}".format(self.replaces_text(raw=user_post_post)),
						"user_post_url": "{}".format(user_post_url),
						"yararule": "{}".format(yararule),
						"full_match": "{}".format(full_match),
						"MD5": "{}".format(md5),
						"SHA256": "{}".format(sha256),
						"mydate": "{}".format(self.today),
						"score": "{}".format(score)
					}

					savedatabase = self.database.save_db(tag="Facebook",
						group_url=self.replaces_text(raw=user_post_url),
						title=self.replaces_text(raw=page_name),
						post=self.replaces_text(raw=user_post_post),
						user_post=self.replaces_text(raw=user_post_name),
						database_path=self.database_path,
						database_name=self.database_name,)

					if savedatabase:
						logs_save_splunk = '{0}/facebook-{1}.json'.format(self.save_log_dir, datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))

						if not os.path.exists(logs_save_splunk):
							 arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
							 arquivo.close()

						arquivo = open(logs_save_splunk, 'r', encoding="utf-8")
						conteudo = arquivo.readlines()
						conteudo.append(json.dumps(infos, ensure_ascii=False)+'\n')
						arquivo = open(logs_save_splunk, 'w', encoding="utf-8")
						arquivo.writelines(conteudo)
						arquivo.close()
