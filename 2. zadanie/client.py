import socket
import threading
import os
import math
import zlib
import time
import datetime

SERVER_PORT = input("server PORT: ")
IP = input("server IP: ")
IP2 = socket.gethostbyname(socket.gethostname())
SERVER_ADDRESS = (IP, int(SERVER_PORT))
print(IP2)

stringM = "m"
stringF = "f"
stringS = "s"

# flags:
txtMsgSent = 1
fileSent = 2
fileInit = 3
folderInit = 4
keepalive = 5
connInit = 6
txtMsgRecv = 7
fileRecv = 8
error = 9
fileInitRecv = 10

initConnection = connInit.to_bytes(1, "little")

textMessage = stringM.encode()
systemMessage = stringS.encode()
fileMessage = stringF.encode()

emptyValue = 0
emptyFrag = emptyValue.to_bytes(2, "little")


filename = ""
filenumber = 0
filepath = ""
flagMessage = ""
numberOfFragments = 0


client = socket.socket(socket.AF_INET,
                       socket.SOCK_DGRAM)
client.bind(("", 9001))


def keepAlive():
    while True:
        time.sleep(5)
        ka = keepalive.to_bytes(1, "little")
        client.sendto(systemMessage+ka, (SERVER_ADDRESS))


t2 = threading.Thread(target=keepAlive)


def receive():
    global filename
    global filenumber
    global filepath
    global flagMessage
    global numberOfFragments
    txtMsgPuzzle = ""
    while True:
        try:
            message, serverAddress = client.recvfrom(1500)
            msgType = message[0]

            if msgType == 115:
                flag = int.from_bytes(message[1:2], "little")
                if flag == 1:
                    print(f"[SYSTEM MESSAGE] Text message has been completed")
                    print(f"[TEXT MESSAGE] {txtMsgPuzzle}")
                    txtMsgPuzzle = ""
                elif flag == 2:
                    absPath = filepath+'/'+filename
                    fileSize = os.path.getsize(absPath)
                    fragmentSize = math.ceil(fileSize/numberOfFragments)
                    print(f"[SYSTEM MESSAGE] File has been built up")
                    print(f"[FILENAME] {filename}")
                    print(f"[FILEPATH] {absPath}")
                    print(f"[FILESIZE] {fileSize} Bytes")
                    print(f"[FILESIZE] {fileSize/1024} KiloBytes")
                    print(f"[FILESIZE] {fileSize/(1024*1024)} MegaBytes")
                    print(f"[FRAGSIZE] {fragmentSize}")
                    print(f"[FRAGMENTS] {numberOfFragments}")
                    filename = ""
                    filepath = ""
                elif flag == 3:
                    print("Please press any key")
                    dstPath = input("Enter the path: ").replace(
                        '\\', '/').replace('"', '')
                    filepath = dstPath
                    if not os.path.exists(filepath):
                        os.makedirs(filepath)
                    srcPath = message[2:].decode('utf-8')
                    splitSrcPath = srcPath.split('/')
                    splitSrcPath.reverse()
                    fileName = splitSrcPath[0].split('.')
                    filename = fileName[0]+"."+fileName[1]
                    path = os.path.join(filepath, filename)
                    filenumber = 2
                    while True:
                        if os.path.isfile(path) == True:
                            filename = fileName[0] + \
                                '('+str(filenumber)+')'+'.'+fileName[1]
                            path = os.path.join(filepath, filename)
                            filenumber += 1
                        else:
                            f = open(path, "x")
                            f.close()
                            print(
                                f"[SYSTEM MESSAGE] File \"{filename}\" has been created")
                            flag = fileInitRecv.to_bytes(1, "little")
                            client.sendto(
                                systemMessage+flag, serverAddress)
                            break
                elif flag == 5:
                    print(f"[KEEPALIVE]")
                elif flag == 6:
                    print(
                        f"[CONNECTION] You have been connected to server {serverAddress}")
                    t2.start()
                    flagMessage = "RECVC"
                elif flag == 7:
                    flagMessage = 'RECVM'
                elif flag == 8:
                    flagMessage = 'RECVF'
                elif flag == 9:
                    flagMessage = 'ERROR'
                elif flag == 10:
                    flagMessage = 'FILEC'
                else:
                    print(f"[SYSTEM MESSAGE] {message[1:].decode('utf-8')}")

            elif msgType == 109:
                actFrag = int.from_bytes(message[1:3], "little")
                ttlFrag = int.from_bytes(message[3:5], "little")
                chSum = int.from_bytes(message[5:9], "little")
                checksum = zlib.crc32(message[9:])
                msgBody = message[9:].decode('utf-8')
                if chSum == checksum:
                    txtMsgPuzzle += msgBody
                    print(f"[TEXT MESSAGE] [{actFrag}/{ttlFrag}] received")
                    flag = txtMsgRecv.to_bytes(1, "little")
                    client.sendto(
                        systemMessage+flag, serverAddress)
                else:
                    print(f"[TEXT MESSAGE] [{actFrag}/{ttlFrag}] error")
                    flag = error.to_bytes(1, "little")
                    client.sendto(
                        systemMessage+flag, serverAddress)

            elif msgType == 102:
                actFrag = int.from_bytes(message[1:3], "little")
                ttlFrag = int.from_bytes(message[3:5], "little")
                chSum = int.from_bytes(message[5:9], "little")
                checksum = zlib.crc32(message[9:])
                fileBody = message[9:]
                numberOfFragments = ttlFrag
                if chSum == checksum:
                    f = open(path, "ab+")
                    f.write(fileBody)
                    f.close()
                    print(f"[FILE MESSAGE] [{actFrag}/{ttlFrag}] received")
                    flag = fileRecv.to_bytes(1, "little")
                    client.sendto(
                        systemMessage+flag, serverAddress)
                else:
                    print(f"[FILE MESSAGE] [{actFrag}/{ttlFrag}] error")
                    flag = error.to_bytes(1, "little")
                    client.sendto(
                        systemMessage+flag, serverAddress)
        except:
            pass


t1 = threading.Thread(target=receive)
t1.start()

connectionCounter = 0

while True:
    client.sendto(
        systemMessage+initConnection, (SERVER_ADDRESS))
    time.sleep(0.5)
    if flagMessage == 'RECVC':
        flagMessage = ""
        break
    elif connectionCounter == 5:
        port = input("server PORT: ")
        ip = input("server IP: ")
        SERVER_ADDRESS = (ip, int(port))
        connectionCounter = 0
    else:
        print(f"[CONNECTION] Server {SERVER_ADDRESS} was not found")
        print(f"[CONNECTION] Reconnecting...")
        connectionCounter = connectionCounter+1
        time.sleep(3)

dissconnectCounter = 0

while True:
    message = input("")
    if message == "file":
        destinationPort = input("Destination PORT: ")
        destinationIp = input("Destination IP: ")
        DEST_ADDRESS = (destinationIp, int(destinationPort))
        while True:
            sizeOfFragment = input("Size of fragment: ")
            if int(sizeOfFragment) >= 1463:
                print("Max size is 1463")
            else:
                break
        sourcePath = input("Source path: ").replace('\\', '/').replace('"', '')
        simulateMistake = input("Simulate mistake (y/n): ")

        if simulateMistake == 'y':
            mistake = input("Number of wrong fragment: ")
        else:
            mistake = -1

        fileSize = os.path.getsize(sourcePath)
        fragSize = int(sizeOfFragment)
        numOfFrags = math.ceil(fileSize/fragSize)
        fileName = sourcePath.split('/')
        fileName.reverse()
        array1 = fileName[0].split('.')
        name = array1[0]+"."+array1[0]

        with open(sourcePath, "rb") as f:
            print(fragSize, fileSize, numOfFrags)
            bytes_read = f.read()
            f.close()

        flag = fileInit.to_bytes(1, "little")
        srcPath = sourcePath.encode()
        client.sendto(systemMessage+flag+srcPath, (DEST_ADDRESS))

        while True:
            if flagMessage == "FILEC":
                time.sleep(0.05)
                flagMessage = ""
                break

        for x in range(numOfFrags+1):
            fragment = bytes_read[(fragSize*x):(fragSize*(x+1))]
            checksum = zlib.crc32(fragment)
            chSum = checksum.to_bytes(4, "little")
            actFrag = x.to_bytes(2, "little")
            ttlFrag = (numOfFrags).to_bytes(2, "little")
            if x == int(mistake):
                errChsum = 0
                err = errChsum.to_bytes(4, "little")
                client.sendto(fileMessage+actFrag+ttlFrag +
                              err+fragment, (DEST_ADDRESS))
                time.sleep(0.05)
            else:
                client.sendto(fileMessage+actFrag+ttlFrag+chSum +
                              fragment, (DEST_ADDRESS))
                time.sleep(0.05)

            while True:
                if flagMessage == "RECVF":
                    print(f"[FILE MESSAGE] [{x}/{numOfFrags}] has been sent")
                    flagMessage = ""
                    break
                elif flagMessage == "ERROR":
                    client.sendto(fileMessage+actFrag+ttlFrag +
                                  chSum+fragment, (DEST_ADDRESS))
                    flagMessage = ""
                    time.sleep(0.05)
                elif flagMessage == "":
                    print("[CONNECTION] Connection has been lost")

        flag = fileSent.to_bytes(1, "little")
        client.sendto(systemMessage+flag, (DEST_ADDRESS))
        print(f"[FILENAME] {name}")
        print(f"[FILEPATH] {sourcePath}")
        print(f"[FILESIZE] {fileSize} Bytes")
        print(f"[FILESIZE] {fileSize / 1024} KiloBytes")
        print(f"[FILESIZE] {fileSize / (1024*1024)} MegaBytes")
        print(f"[FRAGSIZE] {fragSize}")
        print(f"[FRAGMENTS] {numOfFrags}")

    elif message == 'msg':
        while True:
            sizeOfFragment = input("Size of fragment: ")
            if int(sizeOfFragment) >= 1463:
                print("Max size is 1463")
            else:
                break
        messageBody = input("type here: ")
        fragSize = int(sizeOfFragment)
        msgSize = int(len(messageBody))
        numOfFrags = math.ceil(msgSize/fragSize)
        for x in range(numOfFrags):
            partToBeSent = messageBody[(fragSize*x):(fragSize*(x+1))]
            checksum = zlib.crc32(partToBeSent.encode())
            chSum = checksum.to_bytes(4, "little")
            actFrag = x.to_bytes(2, "little")
            ttlFrag = (numOfFrags-1).to_bytes(2, "little")
            client.sendto(textMessage+actFrag+ttlFrag+chSum +
                          partToBeSent.encode(), (SERVER_ADDRESS))
            time.sleep(0.05)

            while True:
                if flagMessage == "RECVM":
                    flagMessage = ""
                    break
                elif flagMessage == "ERROR":
                    flagMessage = ""
                    client.sendto(textMessage+actFrag+ttlFrag+chSum +
                                  partToBeSent.encode(), (SERVER_ADDRESS))
                    time.sleep(0.05)

        flag = txtMsgSent.to_bytes(1, "little")
        client.sendto(systemMessage+flag, (SERVER_ADDRESS))
