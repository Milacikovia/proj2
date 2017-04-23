from base64 import b64encode, b64decode
import socket, os, sys, pickle, select
import RSAlib as rsa
import AESlib as aes

import traceback
import logging

def AESDecryptFile(key, inFile, outFile, chunkSize=64*1024):
    #if not outFile:
        #outFile = "prijateSubory" + '\\' + "Check_" + str(i) + '\\' + "decodePrimes.txt"
        #cur_path = os.path.dirname(__file__)
        #outFile = os.path.relpath('..\\Check_' + str(i) + '\\decodePrimes.txt', cur_path)
  
    with open(inFile, 'rb') as inputF:
        with open(outFile, 'w') as outF:
            while True:
                chunk = inputF.read(chunkSize)
                if len(chunk) == 0:
                    break
                outF.write(aes.decrypt(chunk, key).decode('utf-8'))

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

def changeCertificatesBob(s, host, port, str_KpubB, KpubB, sig_KpubB, KpubCA):
    print("listening...")
    s.listen(5)
    conn, addr = s.accept()

    print ("Connection from: " + str(addr))

    KpubA = pickle.loads(conn.recv(1024))
    #if not KpubA:
    #    return False
    #print("\n1b Received public key from Alice (KpubA)")
    #print(KpubA)

    sig_KpubA = pickle.loads(conn.recv(1024))

    #print("#######################")
    #print(trustConfirm)
    #print("#######################")

    trustConfirm = rsa.verify(KpubA.encode(), b64decode(sig_KpubA), KpubCA)
    input("Overenie certifikatu Alice -> " + str(trustConfirm))

    if not trustConfirm:
        conn.close()
        return False

    print("\n2a [Pickle] Sending my public key (KpubB)\n")
    print(repr(str_KpubB))
    conn.send(pickle.dumps(str_KpubB))
                
    print("\n2a [byteString] Sending my public key (KpubB)\n")
    print(KpubB)
    conn.send(pickle.dumps(KpubB))

    print ("\n3a Sending my signed public key (sig_KpubB)")
    print(sig_KpubB.decode())
    conn.send(pickle.dumps(sig_KpubB))

    input("OK")

    return KpubA, sig_KpubA, trustConfirm

def setAESKeyBob(s, host, port, KprB):
    print("listening...")
    s.listen(5)

    conn, addr = s.accept()
    print ("Connection from: " + str(addr))

    received = conn.recv(1024).decode()
    if not received:
        return False
    print("\n Received Kaes from Alice")

    Kaes = rsa.decrypt(b64decode(received), KprB)
    print(Kaes)

    print("Sending: OK")
    conn.send("OK".encode())
    input("\nDone.")

    return Kaes

def pathsToFiles():
    i = 1
    filename = os.path.dirname(__file__)
    while True:
        relPath = filename + '\\prijateSubory\\Check_' + str(i) + '\\'
        if os.path.exists(os.path.dirname(relPath)):
            i += 1
            continue
        else:
            break
    os.makedirs(os.path.dirname(relPath), exist_ok=True)
 
    pathEncrypted = relPath + '\\encryptedPrimes.enc'
    pathDecrypted = relPath + '\\decryptedPrimes.txt'

    print(pathEncrypted)
    input(pathDecrypted)

    return pathEncrypted, pathDecrypted

def Main():
    host = '127.0.0.1'      # '192.168.137.1'
    port1 = 5000
    port2 = 5050
    KpubB = KprB = ''
    trustConfirm = ''
    path = 'primes.enc'
    pocetOvereni = 1

    while True:
        os.system('CLS')
        if not trustConfirm:
            print("Bob")
        else:
            print("Bob [Alica overena]")
        print("=================================")
        print("1 - Vygeneruj par klucov RSA-1024")
        if KpubB and KprB:
            print("\ta - Vypis sukromny kluc")
            print("\tb - Vypis verejny kluc")
        print("2 - Podpis verejny kluc u CA")   # Poziadaj CA o certifikat
        print("3 - Over si svoj podpisany verejny kluc u CA")
        print("4 - Bud server, ocakavaj sig_KpubA a odosli sig_KpubB")
        if trustConfirm:
            print("---------------------------------")
            print("5 - Vyjednaj tajny kluc pre AES")
            print("6 - Over subor s prvocislami")
        print("=================================")

        cislo = input("-> ")

        if KpubB and KprB:
            if cislo == 'a':
                input(KprB.exportKey('PEM'))
            elif cislo == 'b':
                input(KpubB.exportKey('PEM'))
        if trustConfirm:
            mySocket = socket.socket()
            mySocket.bind((host,port2))
            if cislo == '5':
                try:
                    Kaes = setAESKeyBob(mySocket, host, port2, KprB)
                except:
                    logging.error(traceback.format_exc())
                    input()
                mySocket.close()
            elif cislo == '6' :
                print("listening...")
                mySocket.listen(5)

                conn, addr = mySocket.accept()
                print ("Connection from: " + str(addr))

                pathEncrypted, pathDecrypted = pathsToFiles()
                #pocetOvereni += 1

                with open(pathEncrypted, 'wb') as f:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        f.write(data)
                conn.close()

                try:
                    AESDecryptFile(Kaes, pathEncrypted, pathDecrypted)
                except UnboundLocalError:
                    input("\n[CHYBA]\nTajny kluc pre AES nie je k dispozicii\n")
                except:
                    logging.error(traceback.format_exc())
                    input()
        if cislo == '1':
            (KpubB, KprB) = rsa.newkeys(1024);
            input("Generovane klucov prebehlo uspesne")
        elif cislo == '2':
            mySocket = socket.socket()
            try:
                str_KpubB = str(KpubB.exportKey('PEM'))
                sig_KpubB, KpubCA = getCertificate(mySocket, host, port1, str_KpubB)
            except EOFError:
                input("\n[CHYBA]\nSpojenie bolo prerusene\n")
            except AttributeError:
                input("\n[CHYBA]\nRSA kluce nie su k dispozicii\n")
            except socket.error:
                input("\n[CHYBA]\nNepodarilo sa spojit so serverom\n")
            mySocket.close()
        elif cislo == '3':
            try:
                verify = rsa.verify(str_KpubB.encode(), b64decode(sig_KpubB), KpubCA)
                input("Overenie dopadlo: " + str(verify))
            except UnboundLocalError:
                input("\n[CHYBA]\nCertifikat nie je k dispozicii\n")
        elif cislo == '4':
            mySocket = socket.socket()
            mySocket.bind((host,port2))
            try:
                KpubA, sig_KpubA, trustConfirm = changeCertificatesBob(mySocket, host, port2, str_KpubB, KpubB, sig_KpubB, KpubCA)
            except TypeError:
                input("\n[CHYBA]\nCertifikat nie je doveryhodny\n")
            except UnboundLocalError:
                input("\n[CHYBA]\nRSA kluce alebo certifikat nie je k dispozicii\n")
            except:
                logging.error(traceback.format_exc())
                input()
            mySocket.close()
        elif cislo == 'q':
            break
 
if __name__ == '__main__':
    Main()