import sqlite3

conn = sqlite3.connect('instance/users.db')  # <-- point to the correct location
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
users = cursor.fetchall()

for user in users:
    print(user)

conn.close()
