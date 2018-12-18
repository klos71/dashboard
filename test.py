import sqlite3
import sql

conn = sqlite3.connect('database.db')
print "Opened database successfully";
try:
    nm = "klos"
    addr = "klos@test.com"
    city = "secret"

    conn.execute("INSERT INTO dashboard_users (username,email,password) VALUES (?,?,?)",(nm,addr,city) )
    conn.commit()


except:
    conn.rollback()
    print "error in insert operation"

finally:
    print "Record successfully added"
    conn.close()

print "Table created successfully";
#conn.row_factory = sqlite3.row
#cur = conn.cursor()

#cur.execute('SELECT * FROM dashboard_users')
#rows = cur.fetchall()
#print rows
conn.close()