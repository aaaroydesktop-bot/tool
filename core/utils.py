import os

def clear():

    os.system(
        "cls" if os.name == "nt" else "clear"
    )

def is_admin():

    try:

        return os.geteuid() == 0

    except:

        return False