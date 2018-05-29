import hashlib
import getpass
import re
import os
import pyperclip
import encryption


def print_help():
    print("""Available commands:
    add_password - adds passwords to password database
    get_password - gets you a password from database
    print_logins - prints list of logins that are contained in database (does not print passwords)
    !end - ends loop""")


# This function calculates the hash of the given string
def get_hash(password):
    try:
        check_hash = hashlib.sha256()
        check_hash.update(password)
        return check_hash.hexdigest()
    except UnicodeDecodeError:
        print("Password contains unexpected symbols (note that russian lang is not supported)")


# The log in menu
def log_in():
    # User enters username and password
    user_name = input("User: ")
    user_pass = getpass.getpass("Password: ").encode("utf-8")

    # Reading the userlist
    if "users.txt" not in os.listdir(os.getcwd()):
        return False, None, None

    with open("users.txt", "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
    users = {line.split(':')[0]: line.split(':')[1] for line in lines}

    # If username is in the userlist
    if user_name in users.keys():
        # Calculates the password hash
        pass_hash = get_hash(user_name.encode("utf-8")+user_pass)
        # And checks if it equal to hash in the list
        if users[user_name] == pass_hash:
            return True, user_name, user_pass
        else:
            return False, None, None
    else:
        return False, None, None


# User registration menu
def reg_user():
    # Program reads list of users
    if 'users.txt' not in os.listdir(os.getcwd()):
        open("users.txt", "a")
    with open("users.txt", "rb") as f:
        text = f.read().decode("utf-8")
    lines = text.splitlines()
    users = [line.split(":")[0] for line in lines]

    while 1:
        # User enters username and password
        new_user = input("Username: ")
        new_password = getpass.getpass("Password: ").encode("utf-8")

        # Program checks if the username is in the userlist
        if new_user in users:
            print("Username already exists")
            break
        else:
            # If it's not, program calculates the password hash
            pswd_hash = get_hash(new_user.encode("utf-8") + new_password)

            # And write username and password hash to the file
            out = "{}:{}\n".format(new_user, pswd_hash).encode("utf-8")
            open("users.txt", "ab").write(out)

            # Next program creates a folder for user database
            os.makedirs(os.getcwd() + os.sep + "databases" + os.sep + new_user)
            os.chdir(os.getcwd() + os.sep + "databases" + os.sep + new_user)

            # After that program creates database file and encrypts it
            # First line of file contains username and user password
            output = "{}:{}\n".format(new_user, new_password).encode("utf-8")
            cipher = encryption.AESCipher(new_password)
            encrypted = cipher.encrypt(output)

            open(new_user + ".database", "a")
            with open(new_user + ".database", "w") as f:
                f.write(encrypted)
            os.chdir("..")
            os.chdir("..")
            print("User successfully registered. Now you can log in")
            break


# This function extracts passwords table from database
def get_passwords(username, password):
    os.chdir("databases" + os.sep + username)
    # Function decrypts database
    cipher = encryption.AESCipher(password)
    with open(username + ".database", "r") as f:
        encrypted = f.read()
        text = cipher.decrypt(encrypted)
    if not text:
        os.chdir("..")
        return None

    # Then from decrypted text it extracts line with login and password
    text = text.splitlines()
    passwords_table = {}
    for line in text:
        line = line.strip().split(':')
        passwords_table[line[0]] = line[1]
    os.chdir('..')
    os.chdir('..')
    return passwords_table


# This function creates new passwords database
def db_append(username, password):

    # First function gets password list from database
    passwords = get_passwords(username, password)

    os.chdir("databases" + os.sep + username)
    if username + ".database" not in os.listdir(os.getcwd()):
        open(username + ".database", "a")

    # Next, the begins loop to input
    print("Type data as following: login:password (no whitespaces and :)\n" +
          "Or type !end to stop\n")
    while 1:
        # User enters login:password
        db_create_command = input("@" + username + "(db_append)>")
        pattern = re.compile("^.+\S:.+\S$")
        match = pattern.fullmatch(db_create_command)

        # If entered string matches to the pattern
        if match:
            db_create_command = db_create_command.split(":")
            if db_create_command[0] in passwords.keys():
                print("\n!!!This login is already exists!!!\n")
                continue
            passwords[db_create_command[0]] = db_create_command[1]
        elif db_create_command == "!end":
            break
        elif db_create_command == "":
            continue
        else:
            print("\n!!!Unknown command!!!\n")

    # When input finished, program encrypts data and write it to the file
    output = ""
    for login, login_passwd in zip(passwords.keys(), passwords.values()):
        output += "{}:{}\n".format(login, login_passwd)
    output = output.encode("utf-8")
    cipher = encryption.AESCipher(password)
    with open(username + ".database", "w") as f:
        f.write(cipher.encrypt(output))
    os.chdir("..")
    os.chdir("..")
    print("\nBack to program...\n\nType !end to exit the program\n")


# This is main loop, it begins when user logs in
def main_loop(current_username, current_user_password):
    print("Successfully logged in! Type !end to exit the program")
    while 1:
        main_cicle_command = input("@" + current_username + ">> ")

        # This command kills program process
        if main_cicle_command == "!end":
            break

        # This command allows user to add new passwords to the database
        elif main_cicle_command == "add_password":
            db_append(current_username, current_user_password)

        # This command allows user to extract password. Asked password copies to the clipboard, so user can paste it.
        elif main_cicle_command == "get_password":
            passwords_table = get_passwords(current_username, current_user_password)
            if not passwords_table:
                print("!!!Something went wrong. Database is corrupted or not exists!!!")
            login_from_db = input("Type login: ")
            try:
                pyperclip.copy(passwords_table[login_from_db])
                print("Password to this login was copied to the clipboard")
            except KeyError:
                print("No such login")

        elif main_cicle_command == "print_logins":
            passwords_table = get_passwords(current_username, current_user_password)
            if not passwords_table:
                print("!!!Something went wrong. Database is corrupted or not exists!!!")
            for login in passwords_table.keys():
                print(login)

        elif main_cicle_command == "help":
            print_help()

        else:
            print("!!!Unknown command. To see the manual type 'help'!!!")


if __name__ == "__main__":
    # Here the program begins, user need to log_in to continue
    print("Type 'log_in' to log in or 'register' to register new user. To exit the program type !end")
    while 1:
        command = input("->")
        if command == "log_in":
            login_reply = log_in()
            user_to_login = login_reply[1]
            password_to_login = login_reply[2]
            if login_reply[0]:
                main_loop(user_to_login, password_to_login)
            else:
                print("!!!Username or password is wrong!!!")
        elif command == "register":
            reg_user()
        elif command == "!end":
            break
        else:
            print("!!!No such command!!!")
