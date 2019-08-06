#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__license__ = "GPL"
__version__ = "1.0.1"

import logging
import yaml
import os
import sys
import time
import argparse
from frameworks.twitter import TwitterCrawler
from frameworks.facebook import FacebookCrawler
from frameworks.reddit import RedditCrawler

class SocialMonitor:
	def __init__(self):

		logging.basicConfig(
				level=logging.INFO,
				format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
				datefmt='%Y-%m-%d %H:%M:%S',
		)
		self.logger = logging.getLogger('Start SocialHunter')

		parser = argparse.ArgumentParser()
		parser.add_argument('-c', '--config', help='The directory of the settings file, in Yaml format.',
						   action='store', dest = 'config')
		parser.add_argument('-l', '--loop', help='Set how many times you want to repeat the loop if you want to do it endlessly. Put: 0',
						   action='store', dest = 'loop')
		parser.add_argument('-f', '--framework', help='Enter the framework you want to use. In case you want all inform: all\nAvailable: facebook, reddit, twitter',
						   action='store', dest = 'framework')
		args = parser.parse_args()

		frameworks = ['facebook', 'twitter', 'reddit', 'all']

		if args.framework.lower() in frameworks:
			self.logger.debug('You have entered a valid framework.')
			self.framework = args.framework
		else:
			self.logger.error('Invalid Framework\n')
			sys.exit(1)

		if args.loop:
			if args.loop == '0':
				self.loop = 0
			else:
				if int(args.loop):
					self.loop = int(args.loop)
				else:
					self.logger.error('The number of numbers must be integer.\n')
					sys.exit(1)
		else:
			self.logger.error('Provide a value for the number of loops.\n')
			sys.exit(1)

		if os.path.exists(args.config):
			if '.yml' in args.config:
				with open(args.config, 'r') as stream:
					data = yaml.load(stream, Loader=yaml.FullLoader)
					self.facebook_user = data.get('facebook_user', '')
					self.facebook_passwd = data.get('facebook_passwd', '')
					self.twitter_user = data.get('twitter_user', '')
					self.twitter_passwd = data.get('twitter_passwd', '')
					self.database_name = data.get('database_name', '')
					self.database_path = data.get('database_path', '')
					self.time_scroll = data.get('time_scroll', '')
					self.sleep_time = data.get('sleep_time', '')
					self.path_webdriver = data.get('path_webdriver', '')
					self.headless = data.get('headless', '')
					self.debug = data.get('debug', '')
					self.save_log_dir = data.get('save_log_dir', '')
					self.facebook = data.get('facebook', '')
					self.twitter = data.get('twitter', '')
					self.reddit = data.get('reddit', '')
					self.rule_path = data.get('rule_path', '')

				if self.debug:
					logging.basicConfig(
							level=logging.DEBUG,
							format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
							datefmt='%Y-%m-%d %H:%M:%S',
						)
				else:
					logging.basicConfig(
							level=logging.INFO,
							format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
							datefmt='%Y-%m-%d %H:%M:%S',
						)

				self.logger = logging.getLogger('Start:SocialHunter')
			else:
				self.logger.error('Entered file type is not valid, must be of format yml.\n')
				sys.exit(1)
		else:
			self.logger.error('File does not exist or path is incorrect.\n')
			sys.exit(1)

	@property
	def start(self):
		if self.loop == 0:
			while True:
				self.open()
		else:
			count = 1
			while count <= self.loop:
				count = count+1
				self.open()

	def removelog(self):
		if os.path.exists('geckodriver.log'):
			os.remove('geckodriver.log')

	def open(self):

		if self.framework.lower() ==  'all':
			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Reddit.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorReddit = RedditCrawler(
				dir_webdriver=self.path_webdriver,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.reddit,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorReddit.start
			time.sleep(self.sleep_time)

			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Twitter.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorTwitter = TwitterCrawler(
				dir_webdriver=self.path_webdriver,
				user=self.twitter_user,
				passwd=self.twitter_passwd,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.twitter,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorTwitter.start
			time.sleep(self.sleep_time)


			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Facebook.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorFacebook = FacebookCrawler(
				dir_webdriver=self.path_webdriver,
				user=self.facebook_user,
				passwd=self.facebook_passwd,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.facebook,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorFacebook.start
			time.sleep(self.sleep_time)

		elif self.framework.lower() ==  'facebook':
			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Facebook.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorFacebook = FacebookCrawler(
				dir_webdriver=self.path_webdriver,
				user=self.facebook_user,
				passwd=self.facebook_passwd,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.facebook,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorFacebook.start
			time.sleep(self.sleep_time)

		elif self.framework.lower() ==  'twitter':
			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Twitter.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorTwitter = TwitterCrawler(
				dir_webdriver=self.path_webdriver,
				user=self.twitter_user,
				passwd=self.twitter_passwd,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.twitter,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorTwitter.start
			time.sleep(self.sleep_time)


		elif self.framework.lower() ==  'reddit':
			self.removelog()
			self.logger.info('Starting the Crawler process on the social network Reddit.')
			self.logger.info('Set scroll time: {}.'.format(self.time_scroll))
			self.logger.info('Set sleep time: {}.'.format(self.sleep_time))
			self.logger.info('Debug: {}.'.format(self.debug))
			self.logger.info('Headless: {}.'.format(self.headless))
			self.logger.debug('Getting information from configuration file and sent to class.')
			SocialMonitorReddit = RedditCrawler(
				dir_webdriver=self.path_webdriver,
				headless=self.headless,
				database_name=self.database_name,
				database_path=self.database_path,
				time_scroll=self.time_scroll,
				sleep_time=self.sleep_time,
				save_log_dir=self.save_log_dir,
				dic=self.reddit,
				rule_path=self.rule_path
			)
			self.logger.debug('Information sent by starting the start function.')
			SocialMonitorReddit.start
			time.sleep(self.sleep_time)
try:
	socialmonitor = SocialMonitor()
	socialmonitor.start
except KeyboardInterrupt:
	print('\nIt looks like the script has been terminated by the user.')
	sys.exit(1)
