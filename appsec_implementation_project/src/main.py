
import sys
sys.path.append("/pycrypto/lib")
from functions import *


########################################### MAIN ###########################################

if __name__ == "__main__":
	# FIRST, WE CREATE FILES TO STORE MASTER KEY AND PASSWORDS IF THEY ARE NOT CREATED YET
	setup_files()
	# WE CHECK IF THE USER ALREDY HAS MASTER KEY
	isThereMasterPassword = check_master_password()
	# IF NOT, WE CREATE MASTER KEY EITHER MANUALLY OR AUTOMATICALLY
	if isThereMasterPassword == False:
		while 1:
			AutoGeneratedOption = ask_creating_key_mode()
			if AutoGeneratedOption =="1":
				auto_generate_master_key()
				break
			elif AutoGeneratedOption =="2":
				# WE CREATE MASTER AUTOMATICALLY
				create_master_password()
				break
			else:
				print "ERROR: Invalid choice."


		
	# TO AUTHENTICATE USER, WE ASK THE MASTER KEY TO THE USER
	isMasterPasswordCorrect = ask_master_password()
	# IF THE USER CORRETCLY ENTERS THE MASTER KEY, WE SHOW THE MAIN MENU TO THE USER
	if isMasterPasswordCorrect:
		pair  = read_master_key()
		master_key = pair[1]
		while 1:
			option = ask_options()
			if option == "1":
				# THIS OPTION IS FOR ENTERING NEW RECORD
				username,password = ask_usernamer_password()
				mode = ask_mode()
				add_record(username,password,master_key,mode)
			elif option =="2":
				# THIS OPTION IS QUERYING THE PASSSWORD FILE FOR A GIVEN USERNAME
				query_name= ask_query()
				get_record(query_name,master_key)
			elif option =="3":
				# THIS OPTION IS USED TO CHECK IF A USERNAME, PASSWORD PAIR EXISTS IN THE PASSWORD FILE
				result = False
				username,password = ask_usernamer_password()
				result = check_combination(username,password,master_key)
				if result:
					print "RESULT: The combination exists!"
				else:
					print "RESULT: The combination does not exist."
			elif option =="4":
				# THIS OPTION IS EXITING
				sys.exit("Bye, bye!")
	else:
		# IF THE USER DOES NOT KNOW THE MASTER KEY, WE EXIT
		sys.exit("Wrong password, bye!")




		

















