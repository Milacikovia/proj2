from base64 import b64encode, b64decode
import socket, os, pickle
import RSAlib as rsa
import AESlib as aes

import traceback
import logging

def signCertificate(s, host, port, KprCA, KpubCA):
    print("listening...")
    s.listen(5)

    conn, addr = s.accept()
    print ("Connection from: " + str(addr))
 
    while True:
        KpubK = conn.recv(1024).decode()
        if not KpubK:
            break
        #print("\n1b Received public key from klient (KpubK)")
        #print(KpubK)

        sig_KpubK = b64encode(rsa.sign(KpubK.encode(), KprCA))

        #verify = rsa.verify(KpubK.encode(), b64decode(sig_KpubK), KpubCA)
        #print("@@@@@@@@@@\n\n" + str(verify) + "\n\n@@@@@@@@@@")

        #print("\n2a Sending signed public key from klient (sig_KpubK)\n" + sig_KpubK.decode())

        conn.send(pickle.dumps(sig_KpubK))

        #print ("\n3a Sending my public key (KpubCA)")
        #print(KpubCA.exportKey('PEM'))
        conn.send(pickle.dumps(KpubCA))
 
def Main():
    host = "127.0.0.1"
    port = 5000

    while True:
        os.system('CLS')
        print("Certifikacna autorita [Doveryhodny server]")
        print("=================================")
        print("1 - Vygeneruj par klucov RSA-1024")
        print("2 - Podpis klientov verejny kluc")  # Vystav certifikat
        print("=================================")
        cislo = input("-> ")
        if cislo == '1':
            (KpubCA, KprCA) = rsa.newkeys(1024);
            input("Generovane klucov prebehlo uspesne")
        elif cislo == '2':
            mySocket = socket.socket()
            mySocket.bind((host,port))
            try:
                signCertificate(mySocket, host, port, KprCA, KpubCA)
            except:
                logging.error(traceback.format_exc())
                input()
            mySocket.close()
        elif cislo == 'q':
            break
     
if __name__ == '__main__':
    Main()