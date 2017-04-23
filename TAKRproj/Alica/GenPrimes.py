import math
import random 

def erasthothenovo_sito(limita):
    neni_prvocislo = []
    prvocislo = []

    for i in range(2, limita+1):
        if i not in neni_prvocislo:
            prvocislo.append(i)
            for j in range(i*i, limita+1, i):
                neni_prvocislo.append(j)
    return prvocislo

def vygeneruj_prvocisla():
    limita = int(input("Zadej horni mez pro hledani prvocisel:\n"))
    path = "primes.txt"
    pole = []

    for i in range(0,len(erasthothenovo_sito(limita))):  
        pole.append(erasthothenovo_sito(limita)[i])

    file = open(path,"w+")
    for i in range(0,len(pole)):
        pom_random=random.randrange(1,10)
        if pom_random<=7:
            pomstr = str(pole[i])+'\n'
        elif i<len(pole)-2 and pom_random>7:
            pomstr = str(random.randrange(pole[i],pole[i+1]))+'\n'
        elif pom_random>7:
            pomstr = str(pole[i])+'\n'
        else:
            pomstr = "something went wrong"
        file.write(pomstr)
    file.close()

    input("\nPrvocisla boli ulozene do suboru " + path)
    return path







