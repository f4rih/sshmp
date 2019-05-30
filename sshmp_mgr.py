#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Add 2-Step verification password for your openSSH service.
# Fardin Allahverdinazhand
# 0x0ptim0us@gmail.com


import shutil
import hashlib
import sys
import os
import getpass
import readline
import sqlite3
import optparse
readline.parse_and_bind("tab: complete")

__version__ = "0.1 BETA"
__author__ = "Fardin Allahverdinazhand"
__contact__ = "0x0ptim0us@gmail.com"


if sys.version_info[0] < 3:
	print("Must be using Python 3.x")
	sys.exit()


def print_with_check(msg):
	"""print success messages"""
	print(f"✓ {msg}")


def print_with_error(msg):
	"""print fail messages"""
	print(f"✗ {msg}")


def print_with_info(msg):
	"""print informations"""
	print(f"☛ {msg}")


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


def auth(dbs):
	"""
	Authorizing users for removing SSHMP or changing password
	:param db:
	:return:
	"""
	password = getpass.getpass("Enter master password: ")
	password = password.strip("\n")
	username = getpass.getuser()
	try:
		db = sqlite3.connect(dbs)
	except:
		print("[!] Database not found! exiting ...")
		sys.exit(0)

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


class CheckSystemDependencies(object):
	def __init__(self):
		"""
		check system information and dependencies for installing sshmp
		suck as :
			python executable path location
			logged user home directory
			old version of sshmp if exists
			generate rc,database,sshmp files and directories
		"""
		self.python_executable_path = sys.executable
		self.current_user = getpass.getuser()
		self.current_user_home = os.path.expanduser(f"~{self.current_user}")
		self.current_pwd = os.getcwd()
		self.old_version_exist = self.check_old_versions()
		self.app_dir = os.path.join(self.current_user_home, ".sshmp")
		self.db_loc = os.path.join(self.app_dir, "passwd.db")
		self.ssh_directory = os.path.join(self.current_user_home, ".ssh")
		self.rc_file = os.path.join(self.ssh_directory, "rc")

	def good_to_go(self):
		"""
		Init installer
		:return:
		"""
		# call header
		print_header()
		# everything is ok, call installer
		self.print_system_checks()
		if self.old_version_exist == "False":
			res = input("☛ Process? <y/n>")
			if res.strip("\n") == "y":
				InstallSSHMP()
			else:
				print("Bye!")
		else:
			print_with_info("Some version of SSHMP already installed!")
			print_with_info("Use --uninstall switch for uninstall existing version!")
			sys.exit()

	def print_system_checks(self):
		"""
		print information about installation process
		:return:
		"""
		print_with_check(f"Installing SSHMP for {self.current_user}")
		print_with_check(f"User home directory: {self.current_user_home}")
		print_with_check(f"Python executable path: {self.python_executable_path}")
		print_with_check(f"Old version exists: {self.old_version_exist}")
		print_with_check(f"SSHMP installation directory: {self.app_dir}")
		print_with_check(f"SSHMP database location: {self.db_loc}")

	def check_old_versions(self):
		"""
		check old version of sshmp
		:return:
		"""
		ssh_rc = os.path.join(self.current_user_home, ".ssh/rc")
		try:
			rc_file = open(ssh_rc, "r").read()
		except FileNotFoundError:
			return "False"
		else:
			# there is old version
			if "sshmp.py" in rc_file:
				return "True"
			else:
				return "False"

class InstallSSHMP(CheckSystemDependencies):
	def __init__(self):
		"""
		start installation process
		"""
		super().__init__()
		self.db = ""
		password1 = getpass.getpass("-> Enter master password: ")
		password2 = getpass.getpass("-> Confirm password: ")
		# compare 2 password inserted by user
		if password1.strip("\n") == password2.strip("\n"):
			self.clean_confirmed_password = password1.strip("\n")

			# generate SHA256 hash from password
			hashed_password = hashlib.sha256(self.clean_confirmed_password.encode())
			hashed_password_hexdigest = hashed_password.hexdigest()

			# create directory
			self.create_directory_for_installation(app_dir=self.app_dir)
			# create database for user
			self.create_database(ssh_directory=self.ssh_directory, app_dir=self.app_dir, db_loc=self.db_loc)
			# add username and password to database
			self.insert_into_database(username=self.current_user, hashed_password=hashed_password_hexdigest)
			# create rc file
			self.create_rc_file(app_dir=self.app_dir, rc=self.rc_file)
			print_with_check(f"SSH Master Password successfully enabled for {self.current_user}")
			print_with_check("Please reload/restart sshd service for taking effects")
		# if password did't match
		else:
			# if password did't match call installer again
			print_with_error("Password did not match, try again!")
			InstallSSHMP()


	def create_directory_for_installation(self, app_dir):
		"""
		create directory for SSHMP
		:return:
		"""
		try:
			# create .sshmp directory in user home folder
			os.mkdir(app_dir)
		except FileExistsError:
			print_with_error("SSHMP Folder is exist!")

	def create_database(self, ssh_directory, app_dir, db_loc):
		"""Create database"""
		# check if .sshmp directory not exists try to create it
		if not os.path.exists(ssh_directory):
			os.mkdir(app_dir)

		try:
			# connect to Sqlite database
			self.db = sqlite3.connect(db_loc)
		except Exception as e:
			print_with_error(f"Error: {e}")
			sys.exit()
		self.cursor = self.db.cursor()
		try:

			# create `users` table if not exists
			self.cursor.execute('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')

		except Exception as e:
			print_with_info(f"WARNING: Database is exists!")

		# check if database file exist
		if os.path.exists(db_loc):
			print_with_check("Database created successfully.")

	def insert_into_database(self, username, hashed_password):
		"""
		insert into database
		:return:
		"""
		try:
			self.cursor.execute('''INSERT INTO users(username, password) VALUES(?,?)''', (username, hashed_password))
		except:
			print_with_info("☛ WARNING: User already exists!")
			sys.exit()
		finally:
			self.db.commit()

	def create_rc_file(self, app_dir, rc):
		"""
		create rc file
		:return:
		"""
		# copy sshmp.py to the location
		copy_location = os.path.join(app_dir, 'sshmp.py')
		copy_manager = os.path.join(app_dir, 'sshmp_mgr.py')
		shutil.copy("sshmp.py", copy_location)
		shutil.copy("sshmp_mgr.py", copy_manager)
		try:
			os.symlink(copy_manager, "/usr/local/bin/sshmpmgr")
			print_with_check("Symlink created successfully. run sshmpmgr --help for more info.")
		except:
			print_with_error("Creating symlink failed!")

		print_with_check("SSHMP files copied.")

		# add execute command in rc file
		try:
			rc_file = open(rc, "w")
		except:
			print_with_error("Couldn't create rc file, exiting...")
			sys.exit()
		else:
			sshmp_file = os.path.join(app_dir, "sshmp.py")
			command = f"{self.python_executable_path} {sshmp_file}"

			rc_file.write(f"{command}\n")
			rc_file.close()
			print_with_check("The rc file created successfully.")


class UninstallSSHMP(CheckSystemDependencies):
	def __init__(self):
		"""Uninstall process"""
		super().__init__()

	def uninstall(self):
		# file path of database and sshmp.py
		app_file = os.path.join(self.app_dir, "sshmp.py")
		app_database = os.path.join(self.app_dir, "passwd.db")
		# if authorize
		if auth(app_database):
			# remove command from rc file
			if os.path.exists(self.rc_file):
				try:
					rc = open(self.rc_file, "r+")
					lines = rc.readlines()
					rc.seek(0)
					for line in lines:
						if "sshmp.py" not in line:
							rc.write(line)
					rc.truncate()

				except FileNotFoundError:
					print_with_error("The rc file not found!")
					sys.exit()

			# remove sshmp.py if exist
			if os.path.exists(app_file):
				os.remove(app_file)
			# remove passwd.db file if exists
			if os.path.exists(app_database):
				os.remove(app_database)
			# remove symlink
			if os.path.exists("/usr/local/bin/sshmpmgr"):
				os.remove("/usr/local/bin/sshmpmgr")

			print_with_check("SSHMP removed successfully!")
			print_with_info("Please reload/restart sshd service for taking effects")
		else:
			# if user not authorized then exit
			print_with_error("Operation not permitted!")
			sys.exit()


class Configuration(CheckSystemDependencies):
	def __init__(self):
		super().__init__()
		if auth(self.db_loc):
			res = input(f"☛ Do you want to change password for [{self.current_user}]? <y/n>: ")
			if res.strip("\n") == "y":
				self.change_password()
			else:
				sys.exit()

	def change_password(self):
		"""
		Change password for current user
		:return:
		"""
		password1 = getpass.getpass("-> New password: ")
		password2 = getpass.getpass("-> Confirm password: ")
		# compare 2 password inserted by user
		if password1.strip("\n") == password2.strip("\n"):
			self.clean_confirmed_password = password1.strip("\n")

			# generate SHA256 hash from password
			hashed_password = hashlib.sha256(self.clean_confirmed_password.encode())
			hashed_password_hexdigest = hashed_password.hexdigest()
			# update password
			try:
				db = sqlite3.connect(self.db_loc)
				cursor = db.cursor()
				cursor.execute('''UPDATE users SET password = ? WHERE username = ?''',(hashed_password_hexdigest, self.current_user))
				db.commit()
				print_with_check(f"Password updated for {self.current_user}")
			except Exception as e:
				print_with_error(f"Something wrong! : {e}")
				sys.exit()





if __name__ == "__main__":
	"""Controll switchs"""
	parser = optparse.OptionParser()
	parser.add_option("-i", "--install", action="store_const", const="install", dest="element", help="Install SSHMP for current user")
	parser.add_option("-u", "--uninstall", action="store_const", const="uninstall", dest="element", help="Remove SSHMP if exists")
	parser.add_option("-m" ,"--manage", action="store_const", const="manage", dest="element", help="Change password and settings")
	options, args = parser.parse_args()
	if options.element == "install":
		CheckSystemDependencies().good_to_go()
	elif options.element == "uninstall":
		UninstallSSHMP().uninstall()
	elif options.element == "manage":
		Configuration()
	else:
		print_with_error("Use with --help for more info.")
		sys.exit()