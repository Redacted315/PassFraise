import sqlite3
from os.path import isfile
from crypto_utils import check_password


DB_FILE_PATH = "password_manager.db"
DATA_TABLE = "data_table"
MASTER_HASH_TABLE = "master_table"

class Database:

    def __init__(self):
        self.is_logged_in = False
        self.active_user = None
        if not isfile(DB_FILE_PATH):
            self.first_time_setup()

    def first_time_setup(self):
        con = sqlite3.connect(DB_FILE_PATH)
        cursor = con.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {DATA_TABLE}(
            site TEXT,
            email TEXT,
            username TEXT,
            password TEXT,
            notes TEXT,
            tags TEXT);""")
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {MASTER_HASH_TABLE}(
            profile_username TEXT,
            master_password_hash TEXT);""")
        con.commit()
        con.close()
    
    def add_user(self, profile_username, profile_password_hash):
        con = sqlite3.connect(DB_FILE_PATH)
        cursor = con.cursor()
        cursor.execute(f"INSERT INTO {MASTER_HASH_TABLE}(profile_username, master_password_hash) VALUES (?, ?);", (profile_username, profile_password_hash))
        con.commit()
        con.close()

    def login(self, username, password):
        con = sqlite3.connect(DB_FILE_PATH)
        cursor = con.cursor()
        cursor.execute(f"""SELECT master_password_hash FROM {MASTER_HASH_TABLE} WHERE profile_username = ?""", (username,))
        pswd = cursor.fetchall()[0][0]
        con.close()
        check = check_password(bytes(password, "utf-8"), pswd)
        if not check:
            return False
        self.is_logged_in = True
        return True
    
    def add_password(self, site, email, username, hashed_password, notes, tags):
        if not self.is_logged_in:
            return "not logged in"
        data_tuple = (site, email, username, hashed_password, notes, tags)
        con = sqlite3.connect(DB_FILE_PATH)
        cursor = con.cursor()
        cursor.execute(f"""INSERT INTO {DATA_TABLE}(site, email, username, password, notes, tags) VALUES (?, ?, ?, ?, ?, ?)""", data_tuple)
        con.commit()
        con.close()
    
    def get_all_passwords(self):
        if not self.is_logged_in:
            return "not logged in"
        con = sqlite3.connect(DB_FILE_PATH)
        cursor = con.cursor()
        cursor.execute(f"SELECT * FROM {DATA_TABLE}")
        _ = cursor.fetchall()
        con.close()
        return _








#### testing ####


from crypto_utils import derive_key_from_password, encrypt_data, decrypt_data, generate_salt, get_hashed_password, check_password


# def main():
#     test = Database()
#     profile_name = "matt"
#     profile_password = "ganyu"
#     fernet_key, salt = derive_key_from_password(profile_password)
    
#     # test.first_time_setup(profile_name, get_hashed_password(bytes(profile_password, "utf-8")))
#     # test.add_password("website.com", "email@address.com", "myUserName", encrypt_data(fernet_key, "myPassword123"), "theNotes", "TAG_1")

#     test.login(profile_name, profile_password)
#     print(test.get_all_passwords())

# if __name__ == "__main__":
#     main()