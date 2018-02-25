import string
from random import *
min_char = 8
max_char = 12
def getrandompassword():
    allchar = string.ascii_letters + string.digits
    password = "".join(choice(allchar) for x in range(randint(min_char, max_char)))
    return password
