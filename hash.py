import tkinter as tk
import hashlib
from hashlib import sha256
from hashlib import md5
from hashlib import sha1
from hashlib import sha224
from hashlib import sha384
from hashlib import sha512
from hashlib import sha3_224
from hashlib import sha3_256
from hashlib import sha3_384
from hashlib import sha3_512
from colorama import Fore, Style
from art import *
import os
import time
import sys

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def encode_text(encode_algorithm, input_text):
    encoded_text = encode_algorithm(input_text.encode()).hexdigest()
    return encoded_text

def decode_text(decode_algorithm, input_text):
    decode_text = decode_algorithm(input_text.decode()).hexdigest()
    return decode_text

def show_ascii_art(ascii_art):
    os.system("clear" if os.name == "posix" else "cls")  
    print(ascii_art)
clear_console()

# ASCII obrázek
custom_ascii_art = '''
<!-- ########################## -->
<!-- #  _____           __ _  # -->
<!-- # |__  /__ _ _ __ / _(_) # -->
<!-- #   / // _` | '__| |_| | # -->
<!-- #  / /| (_| | |  |  _| | # -->
<!-- # /____\__,_|_|  |_| |_| # -->
<!-- ########################## -->
'''

show_ascii_art(custom_ascii_art)

input("Stiskněte Enter pro pokračování...")


class ConsoleColors:

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

clear_console()

print(ConsoleColors.GREEN +'''
 _   _           _  __        ___                  _ 
| | | | __ _ ___| |_\ \      / (_)______ _ _ __ __| |
| |_| |/ _` / __| '_ \ \ /\ / /| |_  / _` | '__/ _` |
|  _  | (_| \__ | | | \ V  V / | |/ | (_| | | | (_| |
|_| |_|\__,_|___|_| |_|\_/\_/  |_/___\__,_|_|  \__,_|
                                            [by Zary]''' + ConsoleColors.END)

print("Vítej v apkliaci na decode a encode Hashu.")
print("[01] decode")
print("[02] encode")
print("[03] help")
výběr=input()
    
if výběr == "1":
    výběr2=input("Jaký typ hashe chcete použít na decode ?\n")
    if výběr2 == "sha256":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kód který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha256, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
                print("[01] exit")
                print("[02] main menu")
                výběr3=input()
                if výběr3 == "1":
                     sys.exit()
                else:
                    print("[01] exit")

        if __name__ == "__main__":
                    main()
    
    
    
    elif výběr2 == "md5":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.md5, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")

        if __name__ == "__main__":
                    main()
    
    elif výběr2 == "sha1":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha1, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
        
    elif výběr2 =="sha224":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha224, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    elif výběr2 == "sha384":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha384, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    elif výběr2 == "sha512":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha512, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    elif výběr2 == "sha3_224":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha3_224, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    elif výběr2 == "sha3_256":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha3_256, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    elif výběr2 == "sha3_384":
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha3_384, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")
    else:
        def verify_text(hash_algorithm, input_text, stored_hash):
            input_hash = hash_algorithm(input_text.encode()).hexdigest()
    
            if input_hash == stored_hash:
                    return True
            else:
                return False

        def main():
            stored_hash = input("Zadejte hash kod který chcete rozklíčovat: ")

            wordlist_file = "list.txt"

            try:
                with open(wordlist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        user_input = line.strip()

                        result = verify_text(hashlib.sha3_512, user_input, stored_hash)

                        if result:
                                print(f"Slovo bylo uspěšně nalezeno: '{user_input}")
                                break
                    else:
                        print("Nepodařilo se nalézt slovo z wordlistu.")
            except FileNotFoundError:
                print(f"Soubor '{wordlist_file}' nebyl nalezen.")

elif výběr=="3":
    clear_console()
    print("Příručka")
    print("Decode = odšifrovat")
    print("Encode = zašifrovat")
    print("Všechny typy hashu které můžeš použít:")
    print("sha256")
    print("md5")
    print("sha1")
    print("sha224")
    print("sha384")
    print("sha512")
    print("sha3_224")
    print("sha3_256")
    print("sha3_384")
    print("sha3_512")
else:
    výběr2=input("Jaký typ hashe chcete použít na encode\n")
    if výběr2 == "sha256":
        selected_hash_algorithm = hashlib.sha256
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "md5":
        selected_hash_algorithm = hashlib.md5
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha1":
        selected_hash_algorithm = hashlib.sha1
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha224":
        selected_hash_algorithm = hashlib.sha224
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha384":
        selected_hash_algorithm = hashlib.sha384
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha512":
        selected_hash_algorithm = hashlib.sha512
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha3_224":
        selected_hash_algorithm = hashlib.sha3_224
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha3_256":
        selected_hash_algorithm = hashlib.sha3_256
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    elif výběr2 == "sha3_384":
        selected_hash_algorithm = hashlib.sha3_384
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")
    else:
        selected_hash_algorithm = hashlib.sha3_512
        user_input = input("Jaké slovo chcete za hashovat?\n")
        result = encode_text(selected_hash_algorithm, user_input)
        print(f"Encoded: {result}")