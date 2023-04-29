def tcp_add_to_array(array, packet):
    if len(array) == 0:
        temp = str(packet.src_ip) + " to " + str(packet.dst_ip)
        array.append([])
        array[0].append([temp, packet.src_ip, packet.dst_ip, packet.protocol, packet.flag, packet.frame_number])
        return array
    elif len(array) != 0:
        var1 = str(packet.src_ip) + " to " + str(packet.dst_ip)
        var2 = str(packet.dst_ip) + " to " + str(packet.src_ip)
        for x in range(len(array)):
            if (array[x][0][0] == var1 and array[x][0][3] == packet.protocol) or (array[x][0][0] == var2 and array[x][0][3] == packet.protocol):
                array[x].append([var1, packet.src_ip, packet.dst_ip, packet.protocol, packet.flag, packet.frame_number])
                return array

        array.append([[var1, packet.src_ip, packet.dst_ip, packet.protocol, packet.flag, packet.frame_number]])
        return array

def check_opening_one(array,x):
        if array[x][0][1] == array[x][1][2] == array[x][2][1] and array[x][0][2] == array[x][1][1] == array[x][2][2] and array[x][0][4] == "SYN" and array[x][1][4] == "SYN+ACK" and array[x][2][4] == "ACK":
            return "true"
        else:
            return "false"

def check_opening_two(array,x):
        if array[x][0][1] == array[x][1][2] == array[x][2][1] == array[x][3][2] and array[x][0][2] == array[x][1][1] == array[x][2][2] == array[x][3][1] and array[x][0][4] == "SYN" and array[x][1][4] == "SYN" and array[x][2][4] == "ACK" and array[x][3][4] == "ACK":
            return "true"
        else:
            return "false"

def check_closing_one(array,x):
        temp = len(array[x])
        if array[x][temp-4][1] == array[x][temp-3][2] == array[x][temp-2][1] == array[x][temp-1][2] and array[x][temp-4][2] == array[x][temp-3][1] == array[x][temp-2][2] == array[x][temp-1][1] and array[x][temp-4][4] == "FIN" and array[x][temp-3][4] == "FIN" and array[x][temp-2][4] == "ACK" and array[x][temp-1][4] == "ACK":
            return "true"
        else:
            return "false"

def check_closing_two(array,x):
        temp = len(array[x])
        if array[x][temp-4][1] == array[x][temp-3][2] == array[x][temp-2][1] == array[x][temp-1][2] and array[x][temp-4][2] == array[x][temp-3][1] == array[x][temp-2][2] == array[x][temp-1][1] and array[x][temp-4][4] == "FIN" and array[x][temp-3][4] == "ACK" and array[x][temp-2][4] == "FIN" and array[x][temp-1][4] == "ACK":
            return "true"
        else:
            return "false"

def check_closing_three(array,x):
        temp = len(array[x])
        if array[x][temp-3][2] == array[x][temp-2][1] == array[x][temp-1][2] and array[x][temp-3][1] == array[x][temp-2][2] == array[x][temp-1][1] and array[x][temp-3][4] == "FIN" and array[x][temp-2][4] == "FIN+ACK" and array[x][temp-1][4] == "ACK":
            return "true"
        else:
            return "false"

def check_closing_four(array,x):
        temp = len(array[x])
        if array[x][temp-1][4] == ("RST" or "RST+ACK"):
            return "true"
        else:
            return "false"



def print_tcp(array):
    for x in range(len(array)):
        for y in range(len(array[x])):
            print('x: ', x, 'y: ', y)
            print(array[x][y])

def check_opening_arp(array):
    for x in range(len(array)):
        if check_opening_one(array,x) == "true" or check_opening_two(array,x) == "true":
            print("otvorenie úspešné")
        else:
            print("otvorenie zlyhalo")
        if check_closing_one(array,x) == "true" or check_closing_two(array,x) == "true" or check_closing_three(array,x) == "true" or check_closing_four(array,x) == "true":
            print("zatvorenie úspešné")
        else:
            print("zatvorenie zlyhalo")