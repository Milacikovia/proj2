import socket
import struct
 
def Main():
        #buf = ''
        host = '192.168.137.1'
        port = 5000
         
        mySocket = socket.socket()
        mySocket.connect((host,port))
        """
        while len(buf) < 4:
            buf += mySocket.recv(8)
        num = struct.unpack('!i', buf[:4])[0]
        print("Shared data are " + num)
        """
        message = input(" -> ")
         
        while message != 'q':
                mySocket.send(message.encode())
                data = mySocket.recv(1024).decode()
                 
                print ('Received from server: ' + data)
                 
                message = input(" -> ")
                 
        mySocket.close()
 
if __name__ == '__main__':
    Main()