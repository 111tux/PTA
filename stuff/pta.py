import nmap, sys, csv
import sqlite3, os
import hashlib, atexit
import json
import shutil
import datetime
from termcolor import colored
from random import randint
#--------------------------------------------------------------------#
# GLOBALS
conn        = None
proj        = None
settings    = [None]*3
_mod        = []
sid         = randint(1000000000, 9999999999) # Return a random integer N such that a <= N <= b.
#--------------------------------------------------------------------#
def exit_handler(): # function to go back (with the Backspace button) during terminal input
    os.system('stty -icanon')
atexit.register(exit_handler)
os.system('stty icanon')
#--------------------------------------------------------------------#
def clrs(): # this command clear the text in the terminal for a better overview
    os.system('clear')
#--------------------------------------------------------------------#
def p_logo(): # the logo was defined here
    print(colored('PenTestAutomatizer\n', 'blue'))
    print(colored(" ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ ", "red"))
    print(colored("▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌", "red"))
    print(colored("▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌", "red"))
    print(colored("▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌", "red"))
    print(colored("▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌", "red"))
    print(colored("▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌", "red"))
    print(colored("▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌", "red"))
    print(colored("▐░▌               ▐░▌     ▐░▌       ▐░▌", "red"))
    print(colored("▐░▌               ▐░▌     ▐░▌       ▐░▌", "red"))
    print(colored(" ▀                 ▀       ▀         ▀ \n", "red"))
#--------------------------------------------------------------------#
def create_p(name, hosts, ports, prots, http_s): # function to create a project
    c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
    c.execute("INSERT INTO project  VALUES (NULL, '" + name + "', '" + hosts + "', '" + ports + "', '" + prots + "', '" + http_s + "');")
    conn.commit()   # committing the current transaction.
    os.makedirs("./projects/" + name) # create directory creation
#--------------------------------------------------------------------#
def load_proj(proj_n): # function to load a project
    global conn
    global proj
    c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
    c.execute("SELECT * FROM project;")
    rows = c.fetchall()  # to fetch all rows from the database table
    proj = rows[int(proj_n)]

    clrs()
    p_logo()

    print("load project")
    print("------------------------------------------")
    print("project: " + proj[1] + " loaded")
    print("")
    print("options: ")
    print("")
    print("0     : scan all")
    print("1     : resume")
    print("2     : nmap only")
    print("3     : create report")
    print("------------------------------------------")
    i_nr = input("option: ") # choose one option

    if i_nr == "0": # scan all
        run_nmap()
        working()
        ###########
    elif i_nr == "1": # resume
        working()
    elif i_nr == "2": # nmap only
        run_nmap()
    elif i_nr == "3": # create report
        create_r()
    elif (i_nr != "0" or "1" or "2" or "3"):
        print("enter a valid value!")
    elif (i_abfrage.lower() != "r" or "l" or "c"):
        print("enter a valid value!")
#--------------------------------------------------------------------#
def run_nmap(): # function to run nmap scan
    global proj
    global connect
    global settings

    c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
    nm = nmap.PortScanner() # init; create an instance 
    nm.scan(hosts=proj[2], ports=proj[3], arguments=settings[int(proj[4])])

    iternmcsv = iter(nm.csv().splitlines())
    next(iternmcsv)
    for row in iternmcsv:
        if(row.split(';')[6] == "open"):
            cmd = "INSERT INTO r_nmap VALUES (NULL, " + str(proj[0]) + ", datetime('now', 'localtime')"
            for entr in row.split(';'):
                cmd += ", '" + entr + "'"
            cmd += ", 0);"
            c.execute(cmd)

    conn.commit()   # committing the current transaction.
#--------------------------------------------------------------------#
def run_cmd(mid, hostname, port):
    global proj
    global _mod

    actualdtime = str(datetime.datetime.now())[:-7].replace(' ', '_')   # to get the current time

    cmd = _mod[mid][3].replace("$ip", hostname).replace("$port", port).replace("$out", "./projects/" + proj[1] + "/" + actualdtime + "_" + _mod[mid][0] + "." + _mod[mid][2])

    if settings[2]=="1":
        cmd += " > /dev/null"

    print("[+]" + _mod[mid][0] + " is running!")
    os.system(cmd)
    print("[+]" + _mod[mid][0] + " has finished!")
#--------------------------------------------------------------------#
def working():
    global conn
    global proj
    global _mod

    c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
    c.execute("SELECT * FROM r_nmap WHERE pid=" + str(proj[0]) + " AND status=0;")
    rows = c.fetchall()  # to fetch all rows from the database table
    for row in rows:
        print(row)
        i=0
        for _module in _mod:
            if(row[8] == _module[1]):
                run_cmd(i, row[4], row[7])
            i += 1

        # this row is completed! mark it in the status column
        c.execute("UPDATE r_nmap SET status = 1 WHERE id=" + str(row[0]) + ";")
        conn.commit()   # committing the current transaction.
#--------------------------------------------------------------------#
def create_r():
    global proj
    global _mod
    for f in os.listdir("./projects/" + proj[1] + "/"): # returns a list containing the names of the entries in the directory given by path
        if f != "findings.csv":
            os.system("python3 ./extractors/e_" + f.split('_')[2].split('.')[0] + ".py " + proj[1] + " " + f)   # returns a list of all the words in the string

#--------------------------------------------------------------------#
# main programm starts here!
clrs()
p_logo()

#---- LOAD modules.cfg begin----#
with open('modules.cfg') as fp:
    for row in fp:
        _mod.append(row[:-1].split('<#>'))

with open('settings.cfg') as fp:
    i=0
    for row in fp:
        settings[i] = str(row[:-1])
        i+=1
#---- LOAD modules.cfg end----#

if not os.path.exists("./projects/"):
    os.mkdir("./projects/") # create a directory

if os.path.exists("./pta.sqlite"): # creating sql database(DB)
    conn = sqlite3.connect('pta.sqlite')    # if DB not exists, create DB / if DB exists, connect to database
else:
    sqlite3.connect('pta.sqlite')   # creating sql database
    conn = sqlite3.connect("./pta.sqlite")    # if DB not exists, create DB / if DB exists, connect to database
    c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
    c.execute("CREATE TABLE 'project' ('id' INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,"\
        "'name'  TEXT NOT NULL UNIQUE, "\
        "'hosts' TEXT, "\
        "'ports' TEXT, "\
        "'prots' TEXT, "\
        "'http_s');")
    c.execute("CREATE TABLE 'r_nmap' ('id' INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,"\
        "'pid'  INTEGER, "\
        "'datetime'  TEXT, "\
        "'host'  TEXT, "\
        "'hostname'  TEXT, "\
        "'hostname_type'  TEXT, "\
        "'protocol' TEXT, "\
        "'port' TEXT, "\
        "'name' TEXT,"\
        "'state' TEXT,"\
        "'product' TEXT,"\
        "'extrainfo' TEXT,"\
        "'reason' TEXT,"\
        "'version' TEXT,"\
        "'conf' TEXT,"\
        "'cpe' TEXT,"\
        "'status' INTEGER DEFAULT 0);")

    conn.commit()   # committing the current transaction.

print("main menu:")
print("------------------------------------------")
print("0     : exit programm")
print("1     : create project")
print("2     : load project")
print("3     : delete project")
print("4     : delete database & reload modules")
print("------------------------------------------")
i_nr=input()

######################################################################
if i_nr == "0": # exit the programm
    clrs()
    p_logo()
    print("exit programm")
    print("------------------------------------------")
    print("successfully quit programm!")
    sys.exit()  # quit the programm
######################################################################
elif i_nr == "1": # create a project
    i_abfrage="c" # so that the program can enter the while loop once.

    while (i_abfrage.lower() == "c"): # to create another project
        clrs()
        p_logo()
        print("create project")
        print("------------------------------------------")
        i_proj      = input("project name: ")
        i_hosts     = input("hosts (ip): ")
        i_prot      = input("TCP (0) or UDP (1): ")
        i_port      = input("ports: ")
        i_http_s    = input("http (0) or https (1): ")
        print("")
        create_p(i_proj, i_hosts, i_port, i_prot, i_http_s) # this function create project with given inputs from below from above
        clrs()
        p_logo()
        print("create a project")
        print("------------------------------------------")
        print("project: " + i_proj + " successfully create")
        print("")
        print("press 'r' to return menu:") # open the complete py script
        print("press 'l' to load the project:")
        print("press 'c' to create another project:") # while i_abfrage = c

        i_abfrage=input()
    if (i_abfrage.lower() == "r"): # after creating a project, the py script starts against
        os.system("python3 pta.py")
    elif (i_abfrage.lower() == "l"):
        c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
        c.execute("SELECT COUNT(*) FROM project;")
        load_proj(str(int(c.fetchone()[0])-1)) # load project created above

######################################################################
elif i_nr == "2": # load a project
    clrs()
    p_logo()
    print("load project")
    print("------------------------------------------")
    print("which project would you like to load?")
    print("enter the Number, not the projectname!")
    print("")
    i=0
    c = conn.cursor() # Allows Python code to execute PostgreSQL command in a database session
    c.execute("SELECT * FROM project")
    rows = c.fetchall() # to fetch all rows from the database table
    for row in rows:
        print(str(i) + "     : " + row[1])
        i = i + 1

    print("")
    i_proj  = input("projectname: ")

    load_proj(i_proj)   # function to load project
######################################################################
elif i_nr == "3": # 3. menu function: delete a project
    i_abfrage="d"# so that the program can enter the while loop once.

    while (i_abfrage.lower() == "d"): # to delete a project
        clrs()
        p_logo()
        print("delete project")
        print("------------------------------------------")
        print("which project would you like to delete?")
        print("enter the Number, not the projectname!")
        print("")
        i=0
        c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
        c.execute("SELECT * FROM project ORDER BY id")
        rows = c.fetchall() # to fetch all rows from the database table
        for row in rows:
            print(str(i) + "     : " + row[1])
            i = i + 1

        i_nr = input("projectname: ") # choose a projekt to delete


        sql = "DELETE FROM project WHERE name='" + rows[int(i_nr)][1] + "';"
        c = conn.cursor()   # Allows Python code to execute PostgreSQL command in a database session
        c.execute(sql)
        conn.commit()   # committing the current transaction.
        shutil.rmtree("./projects/" + rows[int(i_nr)][1] + "/")

        clrs()
        p_logo()
        print("delete project")
        print("------------------------------------------")
        print("project: " + i_nr + " successfully delete")
        print("")
        print("press 'r' to return main menu:")
        print("press 'd' to delete another project:") # it is spring back to the while loop

        i_abfrage=input()
    if (i_abfrage.lower() == "r"): # to go back in the menu
        os.system("python3 pta.py") # restart the programm
    elif (i_abfrage.lower() != "r" and i_abfrage.lower() !=  "d"):
        print("enter a valid value!")
######################################################################
elif i_nr == "4": # 4. menu function: delete the database & reloaad the modules
    clrs()
    p_logo()
    print("delete database & reload modules")
    print("------------------------------------------")
    print("")
    print("press 'y' to confirm deletion: ")
    i_load=input()
    while (i_load != "y"):
        print("enter a valid value!")
        i_load=input()
    if (i_load.lower() == "y"): # with the lower() method, programm accept y and Y
        os.remove("pta.sqlite") # delete database
        shutil.rmtree("./projects") # delete an entire directory tree
        os.system("python3 pta.py") # restart the programm
######################################################################
elif i_nr != "1" or "2" or "3" or "4": # last menu function: if your given input unequal with the menu options(1-4), programm restart
    os.system("python3 pta.py") # restart the programm
######################################################################
