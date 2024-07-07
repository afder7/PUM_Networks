import socket as sc
import datetime
import json
import multiprocessing
import random
import hashlib
import signal
import sys
enc = "windows-1251"


def sigint_handler(sig, frame):
    # print(queue, list(filter(lambda t: t, queue)))
    # for thread in filter(lambda t: t, queue):
    #     os.kill(thread.pid, signal.SIGTERM)
    #     thread.close()
    print("mda")

    if users:
        for i, val in users.items():
            if isinstance(val, bytes) and isinstance(i, bytes):
                users[i.decode(enc)] = val.decode(enc)
            elif isinstance(i, bytes):
                users[i.decode(enc)] = val
            elif isinstance(val, bytes):
                users[i] = val.decode(enc)
        with open("C:\\Users\\1\\PycharmProjects\\Networks\\users.json", "w") as uf:
            uf.write(json.dumps(users))

    if current_condition:
        with open("C:\\Users\\1\\PycharmProjects\\Networks\\chat.txt", "w") as cf:
            cf.write(current_condition.decode(enc))

    if rooms:
        for i, val in rooms.items():
            if isinstance(i, bytes):
                rooms[i.decode(enc)] = list(val)
            else:
                rooms[i] = list(val)
        with open("C:\\Users\\1\\PycharmProjects\\Networks\\rooms.json", "w") as rf:
            rf.write(json.dumps(rooms))

    if room_keys:
        for i, val in room_keys.items():
            if isinstance(val, bytes) and isinstance(i, bytes):
                room_keys[i.decode(enc)] = val.decode(enc)
            elif isinstance(i, bytes):
                room_keys[i.decode(enc)] = val
            elif isinstance(val, bytes):
                room_keys[i] = val.decode(enc)
        with open("C:\\Users\\1\\PycharmProjects\\Networks\\rks.json", "w") as rkf:
            rkf.write(json.dumps(room_keys))

    sys.exit()


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
        if message.startswith(b"/create") and len(message.split()) == 2:
            new_room = message.decode(enc).split()[1]
            if new_room not in rooms:
                rooms[new_room] = {login}
                rooms[public].discard(login)
                password = "".join([random.choice('QWERTYUIOPLKJHGFDSAZXCVBNM0123456789') for _ in range(5)])
                room_keys[new_room] = hashlib.sha256(password.encode(enc)).hexdigest()
                client.sendall(f"\rRoom successfully created. Password {password}\n\r".encode(enc))
            else:
                client.sendall(b"\rRoom with this name already exists.\n\r")
        elif message.startswith(b"/join") and len(message.split()) == 3:
            sign_data = message.decode(enc).replace("\r", "").replace("\n", "").split()
            print(sign_data)
            if sign_data[1] not in rooms:
                client.sendall(b"\rRoom does not exist.\n\r")
            else:
                if room_keys[sign_data[1]] != hashlib.sha256(sign_data[2].encode(enc)).hexdigest():
                    client.sendall(b"\rIncorrect password.\n\r")
                else:
                    rooms[public].discard(login)
                    rooms[sign_data[1]].add(login)
                    client.sendall(f"\rSuccessfully entered the room {sign_data[1]}\n\r".encode(enc))
        elif message == b"/exit":
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
                rooms[cur_room].discard(login)
                rooms[public].add(login)
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
                try:
                    if re[count:]:
                        client.sendall(b"".join(re[count:]) + b"\n\r")
                    else:
                        client.sendall(b"".join(re) + b"\n\r")
                except OSError:
                    break
            # client.sendall(b"".join(current_condition.split(b"\n")[count:]) + b"\r\n")
            count = occ


def on_new_client(client, addr):
    global current_condition, rooms
    login = auth(client)
    print(current_condition)
    client.sendall(current_condition)
    count = current_condition.count(b"\n") - current_condition.count(f'{login} ('.encode(enc))
    if all(login not in x for x in rooms.values()):
        rooms[public].add(login)

    # send
    sender = multiprocessing.Process(target=send, args=(client, login))
    receiver = multiprocessing.Process(target=receive, args=(client, count, login))
    # receive

    sender.run()
    receiver.run()


serv = sc.socket(sc.AF_INET,
                 sc.SOCK_STREAM,
                 proto=0)
serv.bind(("", 53210))
signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, sigint_handler)
backlog = 1000
serv.listen(backlog)

# with open("users.json", "r") as uf:
#     ufr = uf.read()
#     print(ufr)
#     if ufr:
#         users = json.loads(uf.read())
#     else:
users = dict()
current_condition = b""
public = "PUBLIC03912810"
rooms = {public: set()}
room_keys = dict()

with open("C:\\Users\\1\\PycharmProjects\\Networks\\users.json", "r") as uf:
    da = uf.read()
    if da:
        users = dict(json.loads(da))
    else:
        users = dict()
with open("C:\\Users\\1\\PycharmProjects\\Networks\\chat.txt", "r") as cf:
    da = cf.read().replace("\n\n\n", "\n\r").replace("\n\n", "\n\r").replace("\n\r\n", "\n\r")
    if da:
        current_condition = da.encode(enc) + b"\r"
    else:
        current_condition = b""
    if current_condition.startswith(b"\n"):
        current_condition = current_condition[2:]
public = "public"
with open("C:\\Users\\1\\PycharmProjects\\Networks\\rooms.json", "r") as rf:
    da = rf.read()
    if da:
        rooms = {x: set(y) for x, y in dict(json.loads(da)).items()}
    else:
        rooms = {public: set()}
with open("C:\\Users\\1\\PycharmProjects\\Networks\\rks.json", "r") as rkf:
    da = rkf.read()
    if da:
        room_keys = dict(json.loads(da))
    else:
        room_keys = dict()
print("IMP")
print(users)
print(current_condition)
print(rooms)
print(room_keys)

while True:
    client, client_addr = serv.accept()
    print(client_addr, "joined the server.")
    if current_condition.count(b"\n") >= 100:
        current_condition = current_condition[current_condition.find(b"\n") + 1:]

    user = multiprocessing.Process(target=on_new_client, args=(client, client_addr))
    user.run()


