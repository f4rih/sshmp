#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Add 2-Step verification password for your openSSH service.
# Fardin Allahverdinazhand
# 0x0ptim0us@gmail.com

__version__ = "0.1 BETA"
__author__ = "Fardin Allahverdinazhand"
__contact__ = "0x0ptim0us@gmail.com"

import getpass
import signal
import sys
import hashlib
import sqlite3
import os
import logging


log_user_home = os.path.expanduser(f"~{getpass.getuser()}")
log_file = os.path.join(log_user_home, '.sshmp/auth.log')
logger = logging.getLogger(__name__)
f_handler = logging.FileHandler(log_file)
f_handler.setLevel(logging.ERROR)
f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)

def print_header():
	header = r"""
   __________ __  ____  _______ 
  / ___/ ___// / / /  |/  / __ \
  \__ \\__ \/ /_/ / /|_/ / /_/ /
 ___/ /__/ / __  / /  / / ____/ 
/____/____/_/ /_/_/  /_/_/      
   SSH Master Password
"""
	print(header)


class Main:
	def __init__(self):
		if sys.stdout.isatty():
			print_header()
			while True:
				signal.signal(signal.SIGTSTP, signal.SIG_IGN)
				result = self.check_pass()
				if result:
					break
				else:
					logger.error("attempts failed")
					continue

	def check_pass(self):
		try:
			password = getpass.getpass("Master password: ")
			password = password.strip()
			if self.pass_validation(password=password):
				return True
			else:
				return False
		except EOFError:
			print()
			self.check_pass()
		except KeyboardInterrupt:
			sys.exit(0)

	@staticmethod
	def pass_validation(password):

		username = getpass.getuser()
		user_home = os.path.expanduser(f"~{username}")
		app_dir = os.path.join(user_home, ".sshmp")
		app_db = os.path.join(app_dir, "passwd.db")

		try:
			db = sqlite3.connect(app_db)
		except:
			return False

		cursor = db.cursor()
		cursor.execute("""SELECT password FROM users WHERE username = ?""", (username,))
		real_password = cursor.fetchone()
		hashed_password = hashlib.sha256(password.encode())
		if hashed_password.hexdigest() == real_password[0]:
			db.close()
			return True
		else:
			db.close()
			return False


if __name__ == "__main__":
	Main()
