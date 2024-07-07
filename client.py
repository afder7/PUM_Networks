import socket
import threading
import sys


def send():
    while True:
        client.sendall((input() + "\n").encode("windows-1251"))


def receive():
    while True:
        print(client.recv(1024).decode("windows-1251"), end="")


host = sys.argv[1]
port = int(sys.argv[2])

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
print(client.recv(1024).decode("windows-1251"), end="")

sender = threading.Thread(target=send)
receiver = threading.Thread(target=receive)

receiver.start()
sender.start()

