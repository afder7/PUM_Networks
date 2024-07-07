import socket as sc
import datetime
import json
import threading
import random
import hashlib
import sys
enc = "windows-1251"


def input_str(client):
    re = b""
    while b'\n' not in re:
        try:
            re += client.recv(1024)
        except ConnectionResetError:
            return
    if re.endswith(b"\r\n") or re.endswith(b"\n\r"):
        re = re[:-2]
    if re.endswith(b"\n") or re.endswith(b"\r"):
        re = re[:-1]

    return re


def auth(client):
    client.sendall(b"Login: ")
    login = input_str(client).decode(enc)
    print(login, "loginn")
    if login not in users.keys():
        client.sendall(b'Seems like this is your first time here. '
                       b'Input the password for future authentications and confirm it by inputting it once more.\r\nPassword: ')
        while login not in users.keys():
            password = input_str(client)
            # client.sendall(b'Confirm password: ')
            print("chego")
            password1 = input_str(client)
            if password1 == password:
                users[login] = hashlib.sha256(password).hexdigest()
                break
            else:
                client.sendall(b'The passwords do not match. Try again\r\nPassword: ')
    else:
        password = b''
        while users[login] != hashlib.sha256(password).hexdigest():
            client.sendall(b'\nPassword: ')
            password = input_str(client)
            if users[login] != hashlib.sha256(password).hexdigest():
                client.sendall(b'Password incorrect \r\n')

    client.sendall(b'\rAuthentication successful. You can start chatting.\r\n')
    print(users, "u")
    with open("users.json", "w") as uf:
        to_json = dict()
        for i, val in users.items():
            if isinstance(val, bytes) and isinstance(i, bytes):
                to_json[i.decode(enc)] = val.decode(enc)
            elif isinstance(i, bytes):
                to_json[i.decode(enc)] = val
            elif isinstance(val, bytes):
                to_json[i] = val.decode(enc)
            else:
                to_json[i] = val
        print(to_json)
        uf.write(json.dumps(to_json, ensure_ascii=False))

    return login


def send(client, login):
    global current_condition
    print(type(client), client.getpeername())
    while True:
        print(login, rooms)
        form = f'\r{login} ({datetime.datetime.now().hour}:{datetime.datetime.now().minute}): '.encode(enc)
        # client.sendall(b"\n\r")
        message = input_str(client)
        if not message:
            break
        if message.startswith(b"/create"):
            new_room = message.decode(enc).split()[1]
            if new_room not in rooms:
                rooms[new_room] = [login]
                rooms[public].remove(login)
                password = "".join([random.choice('QWERTYUIOPLKJHGFDSAZXCVBNM0123456789') for _ in range(5)])
                room_keys[new_room] = password
                client.sendall(f"\rRoom successfully created. Password {password}\n\r".encode(enc))
            else:
                client.sendall(b"\rRoom with this name already exists.\n\r")
        elif message.startswith(b"/join"):
            sign_data = message.decode(enc).replace("\r", "").replace("\n", "").split()
            print(sign_data)
            if sign_data[1] not in rooms:
                client.sendall(b"\rRoom does not exist.\n\r")
            else:
                if room_keys[sign_data[1]] != sign_data[2]:
                    client.sendall(b"\rIncorrect password.\n\r")
                else:
                    rooms[public].remove(login)
                    rooms[sign_data[1]].append(login)
                    client.sendall(f"\rSuccessfully entered the room {sign_data[1]}\n\r".encode(enc))
        elif message.startswith(b"/exit"):
            if login in rooms[public]:
                client.sendall(b"\rYou successfully left the server.\n\r")
                current_condition += f"\r{login} left the server at ({datetime.datetime.now().hour}:{datetime.datetime.now().minute})\n\r".encode(enc)
                client.close()
                break
            else:
                cur_room = None
                for i, val in rooms.items():
                    if login in val:
                        cur_room = i
                        break
                # current_condition += f"\r\n{login} left the room {cur_room} at ({datetime.datetime.now().hour}:{datetime.datetime.now().minute})\n\r".encode(enc)
                rooms[cur_room].remove(login)
                rooms[public].append(login)
                if not rooms[cur_room]:
                    del rooms[cur_room]
                    del room_keys[cur_room]
                client.sendall(f"You left the room {cur_room} and entered the public room\n\r".encode(enc))
        else:
            current_condition += form + message + b"\r\n"
    # print(type(client), client.getpeername())


def receive(client, count, login):
    form = f'{login} ('.encode(enc)
    while True:
        occ = current_condition.count(b"\n") - current_condition.count(f'{login} ('.encode(enc))
        if count != occ:
            cur_room = None
            for i, val in rooms.items():
                if login in val:
                    print(i, "i")
                    cur_room = i
                    break
            re = []
            print(cur_room, "c")
            # print(current_condition.split(b"\n"))
            for x in filter(lambda k: k and k != b"\r", current_condition.split(b"\n")):
                print(x, list(filter(lambda k: k and k != b"\r", current_condition.split(b"\n"))))
                mes = x.decode(enc).split()[0].replace("\r", "").replace("\n", "")
                print(rooms)
                if (mes in rooms[cur_room] and mes != login) or "left the room {cur_room} at (" in mes:
                    re.append(x)
            print(re)
            if re:
                print("yo", re, count)
                if re[count:]:
                    client.sendall(b"".join(re[count:]) + b"\n\r")
                else:
                    client.sendall(b"".join(re) + b"\n\r")
            # client.sendall(b"".join(current_condition.split(b"\n")[count:]) + b"\r\n")
            count = occ


def on_new_client(client, addr):
    global current_condition, rooms
    login = auth(client)
    print(current_condition)
    client.sendall(current_condition)
    count = current_condition.count(b"\n") - current_condition.count(f'{login} ('.encode(enc))
    rooms[public].append(login)

    # send
    sender = threading.Thread(target=send, args=(client, login))
    receiver = threading.Thread(target=receive, args=(client, count, login))
    # receive

    sender.start()
    receiver.start()


serv = sc.socket(sc.AF_INET,
                 sc.SOCK_STREAM,
                 proto=0)
serv.bind((sys.argv[1], int(sys.argv[2])))

backlog = 1000
serv.listen(backlog)

# with open("users.json", "r") as uf:
#     ufr = uf.read()
#     print(ufr)
#     if ufr:
#         users = json.loads(uf.read())
#     else:
users = dict()
hash_fn = basehash.base36()
current_condition = b""
public = "PUBLIC03912810"
rooms = {public: []}
room_keys = dict()

while True:
    client, client_addr = serv.accept()
    print(client_addr, "joined the server.")
    if current_condition.count(b"\n") >= 100:
        current_condition = current_condition[current_condition.find(b"\n") + 1:]

    user = threading.Thread(target=on_new_client, args=(client, client_addr), name=client_addr)
    user.start()


