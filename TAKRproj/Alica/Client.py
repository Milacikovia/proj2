from base64 import b64encode, b64decode
import socket, os, sys, pickle
import GenPrimes as prime
import RSAlib as rsa
import AESlib as aes

import traceback
import logging

def stripNANChars(str):
    str = str.replace("b", "")
    str = str.replace("'", "")
    str = str.replace("\\r\\n", "\r\n")
    return str

def AESencryptFile(key, inFile, outFile=None, chunkSize=64*1024):
    if not outFile:
        outFile = (inFile.rstrip(".txt") + ".enc")   
    with open(inFile, 'rb') as inputF:
        with open(outFile, 'wb') as outF:
            while True:
                chunk = inputF.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = aes.padData(chunk)
                                
                chunk = stripNANChars(chunk)
                outF.write(aes.encrypt(chunk, key))

def getCertificate(s, host, port, KpubK):
    s.connect((host,port))
    s.send(KpubK.encode())

    sig_KpubK = pickle.loads(s.recv(1024))

    #print("\n2b Received signed public key (sig_KpubA)")
    #print(sig_KpubA.decode())

    KpubCA = pickle.loads(s.recv(1024))

    #print("\n3b Received CA public key (KpubCA)")
    #input(KpubCA.exportKey('PEM'))

    return sig_KpubK, KpubCA

def changeCertificatesAlice(s, host, port, KpubA, sig_KpubA, KpubCA):
    s.connect((host,port))

    #print("\n Sending my public key (KpubA)")
    #print(repr(str_KpubA))
    s.send(pickle.dumps(KpubA))

    input("\n Sending my signed public key (sig_KpubA)")
    print(sig_KpubA.decode())
    s.send(pickle.dumps(sig_KpubA))

    str_KpubB = pickle.loads(s.recv(512))
    print("\n [String] Received public key from Bob (str_KpubB)")
    print(str_KpubB)

    pickleKpubB = pickle.loads(s.recv(512))
    print("\n [Pickle] Received public key from Bob (pickleKpubB)")
    print(pickleKpubB)

    sig_KpubB = pickle.loads(s.recv(512))
    print("\n Received signed public key from Bob (sig_KpubB)")
    print(sig_KpubB.decode())

    trustConfirm = rsa.verify(str_KpubB.encode(), b64decode(sig_KpubB), KpubCA)
    input("Overenie certifikatu Boba -> " + str(trustConfirm))

    return str_KpubB, pickleKpubB, sig_KpubB, trustConfirm

def setAESKey(s, host, port, KpubB):
    Kaes = aes.genKey()
    s.connect((host,port))
    #print("\n Sending RSAencrypted Kaes to Bob")
    #print(Kaes)

    encrypted = b64encode(rsa.encrypt(Kaes, KpubB))
    s.send(encrypted)

    reply = s.recv(1024).decode()
    input("Received: " + reply)

    return Kaes

def sendFile(s, host, port, file):
    s.connect((host,port))

    with open(file, 'rb') as f:
        chunk = f.read(1024)
        while chunk:
            s.send(chunk)
            chunk = f.read(1024)

def showFile(file):
    with open(file, 'r') as f:
        chunk = f.read(1024)
        while chunk:
            print(chunk)
            chunk = f.read(1024)
    input("Koniec suboru.")

def Main():
    host = '127.0.0.1'      # '192.168.137.1'
    port1 = 5000
    port2 = 5050
    KpubA = KprA = ''
    trustConfirm = False
    path = ''

    while True:
        os.system('CLS')
        # trustConfirm = Boolean, urcuje ustanovenu doveru medzi Alicou a Bobom
        if not trustConfirm:
            print("Alica")
        else:
            print("Alica [Bob overeny]")
        print("=================================")
        print("0 - Vygeneruj subor s prvocislami (primes.txt)")
        if path:
            print("\tp - Vypis subor s prvocislami")
        print("1 - Vygeneruj par klucov RSA-1024")
        # KpubA, KprA = RSAobject, verejny a privatny kluc Alice
        if KpubA and KprA:
            print("\ta - Vypis sukromny kluc")
            print("\tb - Vypis verejny kluc")
        print("2 - Podpis verejny kluc u CA")   # Poziadaj CA o certifikat
        print("3 - Over svoj podpisany verejny kluc u CA (samooverenie)")
        print("4 - Pripoj sa na Boba, odosli sig_KpubA a ocakavaj sig_KpubB")
        if trustConfirm:
            print("---------------------------------")
            print("5 - Vyjednaj tajny kluc pre AES")
            print("6 - Posli subor s prvocislami")
        print("=================================")

        cislo = input("-> ")

        if KpubA and KprA:
            if cislo == 'a':
                input(KprA.exportKey('PEM'))
            elif cislo == 'b':
                input(KpubA.exportKey('PEM'))
        if path:
            if cislo == 'p':
                try:
                    showFile(path)
                except:
                    logging.error(traceback.format_exc())
                    input()
        if trustConfirm:    
            mySocket = socket.socket()
            if cislo == '5':
                try:
                    Kaes = setAESKey(mySocket, host, port2, pickleKpubB)
                except:
                    logging.error(traceback.format_exc())
                    input()
                mySocket.close()
            if cislo == '6':
                if path:
                    AESencryptFile(Kaes, path)
                else:
                    input("Subor s prvocislami nebol nenajdeny")
                    continue

                encryptedPrimes = (path.rstrip(".txt") + ".enc")  
                try:
                    sendFile(mySocket, host, port2, encryptedPrimes)
                except:
                    logging.error(traceback.format_exc())
                    input()
                mySocket.close()
        if cislo == '0':
            path = prime.vygeneruj_prvocisla()
        elif cislo == '1':
            (KpubA, KprA) = rsa.newkeys(1024);
            input("Generovane klucov prebehlo uspesne")
        elif cislo == '2':
            #print("\n1a Sending my public key (KpubA)")
            #print(KpubA.exportKey('PEM'))
            mySocket = socket.socket()
            try:
                str_KpubA = str(KpubA.exportKey('PEM'))
                sig_KpubA, KpubCA = getCertificate(mySocket, host, port1, str_KpubA)
            except EOFError:
                input("\n[CHYBA]\nSpojenie bolo prerusene\n")
            except AttributeError:
                input("\n[CHYBA]\nRSA kluce nie su k dispozicii\n")
            except socket.error:
                input("\n[CHYBA]\nNepodarilo sa spojit so serverom\n")
            mySocket.close()
        elif cislo == '3':
            try:
                verify = rsa.verify(str_KpubA.encode(), b64decode(sig_KpubA), KpubCA)
                input("Overenie dopadlo: " + str(verify))
            except UnboundLocalError:
                input("\n[CHYBA]\nCertifikat, podpis alebo verejny kluc autority nie je k dispozicii\n")
        elif cislo == '4':
            mySocket = socket.socket()
            try:
                str_KpubB, pickleKpubB, sig_KpubB, trustConfirm = changeCertificatesAlice(mySocket, host, port2, str_KpubA, sig_KpubA, KpubCA)
            except EOFError:
                input("\n[CHYBA]\nDruha strana predcasne ukoncila spojenie\n")
                
            except:
                logging.error(traceback.format_exc())
                input()
            mySocket.close()
        elif cislo == 'q':
            break
 
if __name__ == '__main__':
    Main()