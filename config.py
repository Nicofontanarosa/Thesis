
#################################################################
# File: config.py used by all scripts
#################################################################

import os

def clear_log(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    # Clear the file
    with open(log_file, "w") as f:
        pass  # opening in "w" mode without content clears the file

# Then modify the log_message function to use log_file
def log_message(message, log_file):
    with open(log_file, "a") as f:  # append mode after clearing the file
        f.write(message + "\n")

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')


#################################################################
# End of config.py
#################################################################