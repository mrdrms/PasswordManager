from Crypto.Cipher import AES
import Crypto.Protocol.KDF 
import Crypto.Random 
import Crypto.Util.Counter
import os
import base64
import getpass
import random
import string
import stat
import sys


########################################### VARIABLES ###########################################

# INITIALIZATION VECTOR SIZE FOR CBC AND CTR MODES.
IV_SIZE = 16
# SALT SIZE FOR MASTER KEY
salt_size = 16
# RANDOM SALT FOR MASTER KEY TO MAKE BRUTEFORCE HARDER
salt_for_master = os.urandom(salt_size)
# THIS GIVES US THE CURRENT DIRECTORY
DIR = os.path.dirname(__file__)
# WE DEFINE OUR FILES FOR STORING MASTER KEY AND PASSWORDS
frozen = 'not'
if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS
        print bundle_dir
else:
        # we are running in a normal Python environment
        bundle_dir = os.path.dirname(os.path.abspath(__file__))


MASTER_KEY_FILE = os.path.abspath(os.path.join(bundle_dir, "key_file.txt"))
PASSWORDS_FILE = os.path.abspath(os.path.join(bundle_dir, "passwd_file.txt"))

########################################### HELPER FUNCTIONS ###########################################

def save_master_key(master_password):
	""" 
	This functions is called to save master key to key_file.txt.
	"""
	# WE USER PBKDF1 TO DERIVE A KEY FROM THE MASTER KEY INPUT TAKEN FROM USER
	# 32 IS THE KEY LENGTH
	# 2000 IS NUMBER OF ITERATIONS (MINIMUM RECOMMENDED IS 1000)
	key =Crypto.Protocol.KDF.PBKDF2(master_password, salt_for_master, 32, 2000)
	# AFTER CREATING A DERIVATED KEY, WE SAVE IT TO THE FILE WITH THE SALT ADDED TO IT
	key_file = open(MASTER_KEY_FILE, 'w')
	key_file.write(base64.b64encode(salt_for_master) + ":"+ base64.b64encode(key))
	key_file.close()


def read_master_key():
	""" 
	This functions is used to read master key from key_file.txt.
	"""
	# WE OPEN MASTER KEY FILE, AND SEPATAE IT WITH ":"
	# THEN WE RETURN BOTH SALT AND PASSWORD
	with open(MASTER_KEY_FILE,'r') as f:
		line = f.readline()
		pair = line.split(":")
		return base64.b64decode(pair[0]), base64.b64decode(pair[1])


def create_master_password():
	""" 
	This functions gets input from the user for master key.
	"""
	# WE TAKE MASTER KEY INPUT FROM THE USER AND MAKE SURE HE/SHE ENTERS IT TWO TIMES TO AVOID TYPOS
	# WE HAVE MASTER KEY AT LEAST BE 6 CHARACTERS
	# AFTER THAT, WE CALL save_master_key FUNCTION WITH THE PARAMETER master_password
	while 1:
		master_password = ""
		master_password = getpass.getpass("Please enter master key to create (at least 6 character):");
		if len(master_password) < 6:
			print "ERROR: Master key should be at least 6 characters!"
		else:
			confirmation_password = getpass.getpass("Please retype it:");
			if master_password != confirmation_password:
				print "ERROR: Does not match!"
			else:
				save_master_key(master_password)
				break

def auto_generate_master_key():
	""" 
	This functions automatically generates master key.
	"""
	master_password = base64.b64encode(str(Crypto.Random.new().read(12)));
	save_master_key(master_password)
	print "Your master key: ", master_password


def ask_master_password():
	""" 
	This functions is used to authenticate the user.
	"""
	# WE ASK MASTER KEY TO THE USER TO AUTHENTICATE
	# AFTER GETTING THE INPUT, WE ENCRYPT IT IN THE SAME WAY, AND COMPARE IT WITH THE MASTER KEY SAVE IN THE FILE
	master_password_input = getpass.getpass("To Login, Please enter master password:")
	saved_salt,saved_password = read_master_key()
	master_password_input_key = Crypto.Protocol.KDF.PBKDF2(master_password_input, saved_salt, 32, 2000)
	if master_password_input_key == saved_password:
		return True
	else:
		return False


def check_master_password():
	""" 
	This functions is used to check if the user has master key.
	"""
	# WE CHECK IF THE MASTER KEY FILE EMPTY
	derivated_key=""
	with open(MASTER_KEY_FILE,'r') as f:
		derivated_key = f.readline()
		if derivated_key == "":
			return False
		else:
			return True


def check_name(username):
	""" 
	This functions is used check username.
	"""
	# WE CHECK IF QUERIED NAME EXISTS
	with open(PASSWORDS_FILE,'r') as f:
		for line in f:
			query_username = line.split(":")
			if query_username[0] == username:
				return True
			

def encrypt(username, password,key,mode):
	""" 
	This functions is used to encrypt passwords.
	"""
	# WE CREATE RANDOM SALT FOR EACH PASSWORD 
	salt_for_passwords = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
	# WE LET THE USER SELECT THE MODE
	# FOR CBC AND CTR MODE WE CREATE IV
	# WE ADD SALT TO THE PASWORD AND ENCRYPT IT
	# WE SAVE USERNAME:PASSWORD:IV:[MODE NUMBER 1 FOR ECB, 2 FOR CBC, 3 FOR CTR]
	if mode == "1":
		mode = AES.MODE_ECB
		aes = AES.new(key, mode)
		encrypted_username = aes.encrypt(username+ "\0"*(32-len(username)))
		encrypted_pass = aes.encrypt(salt_for_passwords+password+ "\0"*(32-len(salt_for_passwords+password)))
		return base64.b64encode(encrypted_username)+":"+base64.b64encode(encrypted_pass)+ ":" +" "+":"+ "1"
	elif mode =="2":
		mode = AES.MODE_CBC
		IV = str(Crypto.Random.new().read(IV_SIZE))
		aes = AES.new(key, mode, IV)
		encrypted_username = aes.encrypt(username+ "\0"*(32-len(username)))
		encrypted_pass = aes.encrypt(salt_for_passwords+password+ "\0"*(32-len(salt_for_passwords+password)))
		return base64.b64encode(encrypted_username)+":"+base64.b64encode(encrypted_pass)+":"+base64.b64encode(IV)+ ":" + "2"
	elif mode =="3":
		mode = AES.MODE_CTR
		IV = str(Crypto.Random.new().read(IV_SIZE))
		ctr = Crypto.Util.Counter.new(128, initial_value=long(IV.encode("hex"), 16))
		aes = Crypto.Cipher.AES.new(key, mode, counter=ctr)
		encrypted_username = aes.encrypt(username+ "\0"*(32-len(username)))
		encrypted_pass = aes.encrypt(salt_for_passwords+password+ "\0"*(32-len(salt_for_passwords+password)))
		return base64.b64encode(encrypted_username)+":"+base64.b64encode(encrypted_pass)+":"+base64.b64encode(IV)+ ":" + "3"
	else:
		print "ERROR: Invalid mode!"


def decrypt(encrypted_record,key,mode):
	""" 
	This functions is used to decrypt passwords.
	"""
	# WE DECRYPT THE PASSWORD ACCORDING TO THE MODE IT WAS SAVED
	# WE RETURN USERNAME:PASSWORD
	# decrypted_pass[5:] IS USED TO RETURN THE PASSWORD ONLY (WITHOUT SALT)
	if mode == "1":
		mode = AES.MODE_ECB
		pair = encrypted_record.split(":")
		aes = AES.new(key, mode)
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		decrypted_pass = aes.decrypt(base64.b64decode(pair[1]))
		return decrypted_username+":"+decrypted_pass[5:]
	
	elif mode =="2":
		mode = AES.MODE_CBC
		pair = encrypted_record.split(":")
		aes = AES.new(key, mode,base64.b64decode(pair[2]))
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		decrypted_pass = aes.decrypt(base64.b64decode(pair[1]))
		return decrypted_username+":"+decrypted_pass[5:]

	elif mode =="3":
		mode = AES.MODE_CTR
		pair = encrypted_record.split(":")
		IV = base64.b64decode(pair[2])
		ctr = Crypto.Util.Counter.new(128, initial_value=long(IV.encode("hex"), 16))
		aes = Crypto.Cipher.AES.new(key, mode, counter=ctr)
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		decrypted_pass = aes.decrypt(base64.b64decode(pair[1]))
		return decrypted_username+":"+decrypted_pass[5:]

	else:
		print ""


def decrypt_username(encrypted_record,key,mode):
	""" 
	This functions is used to decrypt usernames.
	"""
	# WE DECRYPT THE PASSWORD ACCORDING TO THE MODE IT WAS SAVED
	# WE RETURN USERNAME:PASSWORD
	# decrypted_pass[5:] IS USED TO RETURN THE PASSWORD ONLY (WITHOUT SALT)
	if mode == "1":
		mode = AES.MODE_ECB
		pair = encrypted_record.split(":")
		aes = AES.new(key, mode)
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		return decrypted_username
	
	elif mode =="2":
		mode = AES.MODE_CBC
		pair = encrypted_record.split(":")
		aes = AES.new(key, mode,base64.b64decode(pair[2]))
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		return decrypted_username

	elif mode =="3":
		mode = AES.MODE_CTR
		pair = encrypted_record.split(":")
		IV = base64.b64decode(pair[2])
		ctr = Crypto.Util.Counter.new(128, initial_value=long(IV.encode("hex"), 16))
		aes = Crypto.Cipher.AES.new(key, mode, counter=ctr)
		decrypted_username = aes.decrypt(base64.b64decode(pair[0]))
		return decrypted_username

	else:
		print ""


def add_record(username,password,key,mode):
	""" 
	This functions is used to add new username:password pair.
	"""
	# IF MODE IS VALID, WE ADD NEW RECORD TO THE FILE
	if mode in ["1","2","3"]:
		if len(password) > 25:
			print "ERROR: Max number of characters for password is 25."
		else:
			encrypted_record = encrypt(username,password,key,mode)
			passwd_file = open(PASSWORDS_FILE, 'a+')
			passwd_file.write(encrypted_record)
			passwd_file.write("\n")
			passwd_file.close()
			print "SUCCESS: Saved!"
	else:
		print "ERROR: Invalid mode!"


def get_record(query_name,key):
	""" 
	This functions is used to retrieve record from the file according to the username queried.
	"""
	# WE GET RECORD FROM passwd_file.txt FILE, ACCORDING TO THE GIVEN INPUT QUERY NAME
	with open(PASSWORDS_FILE,'r') as f:
	    for line in f:
	    	pair = line.split(":")
	    	username = decrypt_username(line.rstrip(),key,pair[3].strip())
	    	if username.rstrip('\x00') == query_name:
	    		combination = decrypt(line.rstrip(),key,pair[3].strip())
	    		print "FOUND: ", combination


def check_combination(username,password,key):
	""" 
	This functions is used to check if username, password combination exists.
	"""
	# WE CHECK IF GIVEN USERNAME, PASSWORD PAIR EXISTS IN passwd_file.txt FILE
	with open(PASSWORDS_FILE,'r+') as f:
	    for line in f:
	    	pair = line.split(":")
	    	username_queried = decrypt_username(line.rstrip(),key,pair[3].strip())
	    	if username_queried.rstrip('\x00') == username:
	    		combination = decrypt(line.rstrip(),key,pair[3].strip())
	    		username_pass = combination.split(":")
	    		if username_pass[1].rstrip('\x00') == password.rstrip():
	    			return True



def ask_options():
	""" 
	This functions gives options for the main menu
	"""
	op = raw_input("To enter new record, enter 1\nTo lookup existing record, enter 2\nTo check username/password combination, enter 3\nTo exit, enter 4: ")
	return op



def ask_usernamer_password():
	""" 
	This functions is called to get username, password input from the user
	"""
	username = raw_input("Please enter username:")
	password = raw_input("Please enter password:")
	return username.strip(),password.strip()


def ask_query():
	""" 
	This functions is called to ask the name that will be queried to find username:password combination
	"""
	query_name = raw_input("Query - Please enter username:")
	return query_name.strip()


def ask_mode():
	""" 
	This functions is called to ask which encryption mode to use
	"""
	query_name = raw_input("For ECB:1,CBC:2,CTR:3. Enter mode number:")
	return query_name.strip()


def setup_files():
	""" 
	This functions is called to create key_file.txt and passwd_file.txt
	Permissions of the files are changed, so only the owner of the files can read from and write to the files.
	"""
	if os.path.isfile(PASSWORDS_FILE)!= True :
		file_passwd = open(PASSWORDS_FILE, 'w+')
		file_passwd.close()
		os.chmod(PASSWORDS_FILE, stat.S_IREAD | stat.S_IWRITE)

	if os.path.isfile(MASTER_KEY_FILE)!= True :
		file_passwd = open(MASTER_KEY_FILE, 'w+')
		file_passwd.close()
		os.chmod(MASTER_KEY_FILE, stat.S_IREAD | stat.S_IWRITE)

		
def ask_creating_key_mode():
	""" 
	This functions is called to ask if user wants auto generated master key or not
	"""
	op = raw_input("We need to create master key\nIf you want auto generated, enter 1\nIf you want to create it manually, enter 2: ")
	return op.strip()