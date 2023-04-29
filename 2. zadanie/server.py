import socket
import threading
import math
import time
import zlib
import os
import datetime

SERVER = socket.gethostbyname(socket.gethostname())
SERVER_PORT = input("PORT: ")
print('IP tohto počítača je: ', SERVER)


SERVER_ADDRESS = ("", int(SERVER_PORT))
FORMAT = 'utf-8'

server = socket.socket(socket.AF_INET,
                       socket.SOCK_DGRAM)


server.bind(SERVER_ADDRESS)

stringM = "m"
stringF = "f"
stringS = "s"

# flags:
txtMsgSent = 1
fileSent = 2
fileInitSent = 3
folderInitSent = 4
keepalive = 5
connRecv = 6
txtMsgRecv = 7
fileRecv = 8
error = 9
fileInitRecv = 10


recvConnection = connRecv.to_bytes(1, "little")

textMessage = stringM.encode()
systemMessage = stringS.encode()
fileMessage = stringF.encode()

emptyValue = 0
emptyFrag = emptyValue.to_bytes(2, "little")

filename = ""
filenumber = 0
filepath = ""
flagMessage = ""

CLIENT_ADDRESS = ""
numberOfFragments = 0
lastFrag = 0


def receive():
    global filename
    global filenumber
    global filepath
    global flagMessage
    global CLIENT_ADDRESS
    global numberOfFragments
    global lastFrag
    txtMsgPuzzle = ""
    while True:
        try:
            message, clientAddress = server.recvfrom(1500)
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
                            server.sendto(
                                systemMessage+flag, clientAddress)
                            break
                elif flag == 5:
                    print(f"[KEEPALIVE]")
                    flag = keepalive.to_bytes(1, "little")
                    server.sendto(systemMessage+flag, clientAddress)
                elif flag == 6:
                    CLIENT_ADDRESS = clientAddress
                    print(
                        f"[CONNECTION] {CLIENT_ADDRESS} has been connected to server")
                    server.sendto(systemMessage+recvConnection, clientAddress)
                elif flag == 7:
                    flagMessage = 'RECVM'
                elif flag == 8:
                    flagMessage = 'RECVF'
                elif flag == 9:
                    flagMessage = 'ERROR'
                elif flag == 10:
                    flagMessage = 'FILEC'
                else:
                    print("netusim co sa tu deje")
                    print(f"[SYSTEM MESSAGE] {message[1:].decode('utf-8')}")

            elif msgType == 109:
                actFrag = int.from_bytes(message[1:3], "little")
                ttlFrag = int.from_bytes(message[3:5], "little")
                chSum = int.from_bytes(message[5:9], "little")
                checksum = zlib.crc32(message[9:])
                msgBody = message[9:].decode('utf-8')
                if chSum == checksum:
                    txtMsgPuzzle += msgBody
                    flag = txtMsgRecv.to_bytes(1, "little")
                    server.sendto(
                        systemMessage+flag, clientAddress)
                else:
                    print(f"[TEXT MESSAGE] [{actFrag}/{ttlFrag}] error")
                    flag = error.to_bytes(1, "little")
                    server.sendto(
                        systemMessage+flag, clientAddress)

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
                    server.sendto(
                        systemMessage+flag, clientAddress)
                else:
                    print(f"[FILE MESSAGE] [{actFrag}/{ttlFrag}] error")
                    flag = error.to_bytes(1, "little")
                    server.sendto(
                        systemMessage+flag, clientAddress)
        except:
            pass


t1 = threading.Thread(target=receive)
t1.start()


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

        flag = fileInitSent.to_bytes(1, "little")
        srcPath = sourcePath.encode()
        server.sendto(systemMessage+flag+srcPath, (DEST_ADDRESS))

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
                server.sendto(fileMessage+actFrag+ttlFrag +
                              err+fragment, (DEST_ADDRESS))
                time.sleep(0.05)
            else:
                server.sendto(fileMessage+actFrag+ttlFrag+chSum +
                              fragment, (DEST_ADDRESS))
                time.sleep(0.05)

            while True:
                if flagMessage == "RECVF":
                    flagMessage = ""
                    break
                elif flagMessage == "ERROR":
                    server.sendto(fileMessage+actFrag+ttlFrag +
                                  chSum+fragment, (DEST_ADDRESS))
                    flagMessage = ""
                    time.sleep(0.05)

        flag = fileSent.to_bytes(1, "little")
        server.sendto(systemMessage+flag, (DEST_ADDRESS))
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
            server.sendto(textMessage+actFrag+ttlFrag+chSum +
                          partToBeSent.encode(), (CLIENT_ADDRESS))
            time.sleep(0.5)

            while True:
                if flagMessage == "RECVM":
                    flagMessage = ""
                    break
                elif flagMessage == "ERROR":
                    server.sendto(textMessage+actFrag+ttlFrag+chSum +
                                  partToBeSent.encode(), (CLIENT_ADDRESS))
                    flagMessage = ""
                    time.sleep(0.5)
        flag = txtMsgSent.to_bytes(1, "little")
        server.sendto(systemMessage+flag, (CLIENT_ADDRESS))
