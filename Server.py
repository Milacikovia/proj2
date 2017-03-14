import socket
import random
import struct
 
def Main():
    #primes = ['2','3','5','7','11','13','17','19','23','29','31','37','41','43','47','53']
    host = "127.0.0.1"
    port = 5000
     
    mySocket = socket.socket()
    mySocket.bind((host,port))

    #DHp, DHg = primes[random.randrange(len(primes))], random.randrange(2, 20)
    #print(DHp, DHg)
    
    mySocket.listen(1)
    conn, addr = mySocket.accept()

    print ("Connection from: " + str(addr))

    #dat = struct.pack(DHp)
    #conn.send(dat)
    while True:
            data = conn.recv(1024).decode()
            if not data:
                    break
            print ("from connected  user: " + str(data))
            
            data = str(data).upper()
            print ("sending: " + str(data))
            conn.send(data.encode())
            
    conn.close()
     
if __name__ == '__main__':
    Main()