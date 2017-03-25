# Autor: Adam Varga, xvarga11@stud.feec.vutbr.cz
# Predmet: Aplikovana kryptografia [TAKR]

import random   # generator pseudonahodnych cisel - random.randrange()
import sys      # korektne ukoncenie programu - sys.exit()
import os       # mazanie konzoly - os.system()

# Funkcia na pravdepodobnostny test prvociselnosti Miller-Rabin
# Parametre: n - testovane cislo
#            k - presnost testu
# Navratova hodnota: True, ak n je pravdepodobne prvocislo
#                    False, ak n je zlozene cislo

def millerRabin(n, k) :
    if n < 2 or (n > 2 and n % 2 == 0) or k < 1 :
        return False
    d = (n - 1) / 2
    s = 1
    while(d % 2 == 0) :
        d /= 2
        s += 1
    flag = 0
    d = int(d)  # S celociselnym datovym typom modulo pracuje korektne
    for _ in range(k) :
        a = random.randrange(1, n)  # generator pseudonahodnych cisel od 1 do n -1
            ### s = 0
        x = pow(a, d) % n
        if x == 1 or x == n - 1 :
            continue
            ### s = 1
        x = pow(a, 2*d) % n
        if x == 1 :
            return False
        if x == n - 1 :
            continue
            ### s >= 2
        for ss in range(1, s) :
            x = pow(a, pow(2, ss) * d) % n
            if x == 1 :
                return False
            if x == n - 1 :
                flag = 1
                break
        if flag == 1 :
            flag = 0
            continue
        else:
            return False
    return True

while(True):
    print("Test prvociselnosti Miller-Rabin\n")
    choice = input("Vyberte subor:\n1 - subor obsahujuci cisla aj prvocisla\n2 - subor s ukazkou syntaktickych chyb\nq - Ukoncenie programu")
    if choice == '1':
        file = "python_project1_mjurek/prvocisla_s_chybou.txt"
        break
    elif choice == '2':
        file = "trashprimes.txt"
        break
    elif choice == 'q':
        sys.exit()
    else:
        os.system('cls' if os.name == 'nt' else 'clear')    # Vymazanie konzoly
        
precision = int(input("\nZadajte presnost testu Miller-Rabin [odporucanie je v rozmedzi 12-25]: "))

with open(file, "r") as f :
        
    for line in f :
        if not line : break
        num = line.strip('\n')
        if not num.isdigit() : continue
        if(millerRabin(int(num), precision)) :
            print("Cislo", num, "je pravdepodobne prvocislo")
        else :
            print("Cislo" , num, "nie je prvocislo")

input("Koniec suboru. Stlace lubovolnu klavesu")
# with zatvori subor