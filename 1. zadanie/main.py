import math
import scapy.all as scapy
import ruamel.yaml

from tcp import tcp_add_to_array
from tcp import check_opening_arp
from tcp import print_tcp
from udp import filter_udp

from udp import udp_add_to_array

from arp import arp_add_to_array
from arp import filter_arp

from icmp import icmp_add_to_array

temp_name = "vzorky/"
file_name = "z1-final.pcap"
file = temp_name + file_name

#initializing global vars

dictionary = {
    "name": "PKS2022/23",
    "pcap_name": "all.pcap"
}
packets = []

packet_field = scapy.rdpcap(file)


#array of TCP,UDP packets

tcp_packets = []
udp_packets = []
icmp_packets = []
arp_packets = []


temp_bool_arp = "false"

#creating packet object

class Packet:
    frame_number = None
    frame_len_pcap = None
    frame_len_medium = None
    frame_type = None
    src_mac = None
    dst_mac = None
    ether_type = None
    sap = None
    pid = None
    arp_opcode = None
    src_ip = None
    dst_ip = None
    id = None
    flags_mf = None
    frag_offset = None
    protocol = None
    icmp_type = None
    src_port = None
    dst_port = None
    app_protocol = None
    hexa_frame = None

    sender_node = None
    sender_number_of_sent_packets = None

    communication_number_comm = None
    communication_src_comm = None
    communication_dst_comm = None
    communication_packets = None

    partial_communication_number_comm = None
    partial_communication_packets = None

    def __init__(self, frame_number, len_frame_pcap, len_frame_medium, frame_type, src_mac, dst_mac):
        self.frame_number = frame_number
        self.len_frame_pcap = len_frame_pcap
        self.len_frame_medium = len_frame_medium
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac


#Source_IPv4_Addresses array & Destionation_IPv4_Addresses array

Source_IPv4_Addresses = []
Destination_IPv4_Addresses = []



#Source_IPv4_Address object & Destination_IPv4_Address object

class Source_IPv4():
    id = None
    value = 1


class Destination_IPv4():
    id = None
    value = 1



#Single packet in TCP communication

class single_packet:
    frame_number = None
    src_port = None
    dst_port = None
    src_mac = None
    dst_mac = None
    src_ip = None
    dst_ip = None
    len_pcap = None
    len_medium = None
    frame_type = None
    ether_type = None
    flag = None
    protocol = None
    app_protocol = None
    arp_opp = None
    hex_frame = None



#search for object

def search_for_Object(name, array):
    for i in range(len(array)):
        if array[i].id == name:
            array[i].value = array[i].value+1
            return array[i]
    return None



#count values in array

def count_values(array):
    temp = 0
    for j in range(len(array)):
        temp = temp + array[j].value
    return temp



#format printout

def number_of_tabs(string):
    if len(string) > 14:
        return 3
    elif len(string) <11:
        return 5
    else:
        return 4



#function for reading external files

def get_key_value(key, file):
    with open(file) as f:
        for line in f:
            name, value = line.partition("&")[::2]
            if key == name:
                return value.replace("\n", "")



#function for styling hexa_frame

def get_hexa_frame(string):
    new_string = ""
    for x in range(0, len(string), 2):
        if (x + 2) % 32 == 0 and x != 0 and x <len(string) - 2:
            new_string = new_string + string[x:x+2] + "\n"
        else:
            if x < len(string) - 2:
                new_string = new_string + string[x:x + 2] + " "
            else:
                new_string = new_string + string[x:x + 2]
    return new_string+"\n"



#function fot formating mac_dst and mac_src

def get_mac_format(string):
    new_string = ''
    for x in range(0, len(string), 2):
        if x < len(string)-2:
            new_string = new_string + string[x:x+2] + ":"
        else:
            new_string = new_string + string[x:x+2]
    return new_string



#converts to hexadecimal

def convert_to_dec(temp):
    dec = int(temp, 16)
    return dec



#convert to IP format

def get_ip_format(string):
    new_string = ''
    for x in range(0, len(string), 2):
        if x < len(string)-2:
            new_string = new_string + str(convert_to_dec(string[x:x+2])) + "."
        else:
            new_string = new_string + str(convert_to_dec(string[x:x+2]))
    return new_string



#checks if ethernet

def check_if_ethernet(value):
    if value > 1500:
        return "true"
    else:
        return "false"



#check if 802.3 and returns which one

def check_802(string):
    if string == 'FF':
        return "IEEE 802.3 RAW"
    if string == "AA":
        return "IEEE 802.3 LLC & SNAP"
    else:
        return "IEEE 802.3 LLC"



#alternate main

for i in range(len(packet_field)):
    frame = scapy.raw(packet_field[i]).hex()


#frame_type

    frame_type_ethernet = frame[24:28]
    frame_type_llc = frame[28:30].upper()

    dec_frame = convert_to_dec(frame_type_ethernet)

    if check_if_ethernet(dec_frame) == 'true':
        type = 'ETHERNET II'
    else:
        type = check_802(frame_type_llc)


#frame_len_pcap & frame_len_medium

    frame_len_pcap = math.trunc(len(frame)/2)

    if frame_len_pcap < 64:
        frame_len_pcap = 64

    frame_len_medium = math.trunc(frame_len_pcap + 4)


#src_mac & dst_mac

    mac_dst = get_mac_format(frame[0:12].upper())
    mac_src = get_mac_format(frame[12:24].upper())


#new packet object

    packet = Packet(i+1, frame_len_pcap, frame_len_medium, type, mac_src, mac_dst)


#hexa_frame

    hexa_frame_with_style = get_hexa_frame(frame.upper())
    packet.hexa_frame = ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame_with_style)


#pid & sap

    llc_sap = frame[28:30].upper()
    llc_raw_pid = frame[40:44].upper()

    if type == "IEEE 802.3 LLC":
        packet.sap = get_key_value(llc_sap,"sap.txt")

    if type == "IEEE 802.3 LLC & SNAP":
        packet.pid = get_key_value(llc_raw_pid,"pid.txt")


#ether_type

    if type == "ETHERNET II":
        packet.ether_type = get_key_value(frame_type_ethernet,"ethernet_protocols.txt")


#src_ip & dst_ip

    if packet.ether_type == "ARP":
        packet.src_ip = get_ip_format(frame[56:64])
        packet.dst_ip = get_ip_format(frame[76:84])
        packet.arp_opcode = get_key_value(frame[40:44], "arp_opcode.txt")

#filter ARP

        single_packet.frame_number = packet.frame_number

        single_packet.src_ip = packet.src_ip
        single_packet.dst_ip = packet.dst_ip
        single_packet.src_mac = packet.src_mac
        single_packet.dst_mac = packet.dst_mac

        single_packet.len_pcap = packet.len_frame_pcap
        single_packet.len_medium = packet.len_frame_medium

        single_packet.frame_type = packet.frame_type
        single_packet.ether_type = packet.ether_type

        single_packet.hex_frame = packet.hexa_frame

        single_packet.arp_opp = packet.arp_opcode

        temp_array_arp = arp_add_to_array(arp_packets, single_packet)


    if packet.ether_type == "IPv4":
        packet.src_ip = get_ip_format(frame[52:60])
        packet.dst_ip = get_ip_format(frame[60:68])

#task 3

        if search_for_Object(packet.src_ip, Source_IPv4_Addresses) == None:
            new_src_ip_address = Source_IPv4()
            new_src_ip_address.id = packet.src_ip
            Source_IPv4_Addresses.append(new_src_ip_address)

        if search_for_Object(packet.dst_ip, Destination_IPv4_Addresses) == None:
            new_dst_ip_address = Destination_IPv4()
            new_dst_ip_address.id = packet.dst_ip
            Destination_IPv4_Addresses.append(new_dst_ip_address)


#protocol

        packet.protocol = get_key_value(frame[46:48], "IPv4_protocols.txt")


#ICMP filter

        if packet.protocol == "ICMP":
            single_packet.src = packet.src_ip
            single_packet.dst = packet.dst_ip
            single_packet.flag = get_key_value(str(frame[94:96]), "flags.txt")
            single_packet.protocol = packet.app_protocol
            single_packet.order = packet.frame_number
            temp_array_icmp = icmp_add_to_array(tcp_packets, single_packet)

#src_port & dst_port

        if packet.protocol == "TCP" or packet.protocol == "UDP":
            packet.src_port = convert_to_dec(frame[68:72])
            packet.dst_port = convert_to_dec(frame[72:76])

#app_protocol

            packet.app_protocol = get_key_value(str(packet.src_port),"known_ports.txt")
            if packet.app_protocol == None:
                packet.app_protocol = get_key_value(str(packet.dst_port),"known_ports.txt")



#filter TCP & UDP

        if packet.protocol == "TCP":
            single_packet.frame_number = packet.frame_number

            single_packet.src_port = packet.src_port
            single_packet.dst_port = packet.dst_port
            single_packet.src_mac = packet.src_mac
            single_packet.dst_port = packet.dst_mac
            single_packet.src_ip = packet.src_ip
            single_packet.dst_ip = packet.dst_ip

            single_packet.len_pcap = packet.frame_len_pcap
            single_packet.len_medium = packet.frame_len_medium

            single_packet.frame_type = packet.frame_type
            single_packet.ether_type = packet.ether_type

            single_packet.flag = get_key_value(str(frame[94:96]), "flags.txt")

            single_packet.hex_frame = packet.hexa_frame

            temp_array_tcp = tcp_add_to_array(tcp_packets, single_packet)


        if packet.protocol == "UDP":
            single_packet.frame_number = packet.frame_number

            single_packet.src_port = packet.src_port
            single_packet.dst_port = packet.dst_port
            single_packet.src_mac = packet.src_mac
            single_packet.dst_mac = packet.dst_mac
            single_packet.src_ip = packet.src_ip
            single_packet.dst_ip = packet.dst_ip

            single_packet.len_pcap = packet.len_frame_pcap
            single_packet.len_medium = packet.len_frame_medium

            single_packet.ether_type = packet.ether_type
            single_packet.frame_type = packet.frame_type
            single_packet.protocol = packet.protocol
            single_packet.app_protocol = packet.app_protocol

            single_packet.hex_frame = packet.hexa_frame

            temp_array_udp = udp_add_to_array(udp_packets, single_packet)







#printing out

    packet_dictionary = {   "frame_number": packet.frame_number,
                             "len_frame_pcap": packet.len_frame_pcap,
                             "len_frame_medium": packet.len_frame_medium,
                             "frame_type": packet.frame_type,
                             "src_mac": packet.src_mac,
                             "dst_mac": packet.dst_mac,
                             }

    if packet.ether_type != None:
        packet_dictionary["ether_type"] = packet.ether_type

    if packet.sap != None:
        packet_dictionary["sap"] = packet.sap

    if packet.pid != None:
        packet_dictionary["pid"] = packet.pid

    if packet.arp_opcode != None:
        packet_dictionary["arp_opcode"] = packet.arp_opcode

    if packet.src_ip != None:
        packet_dictionary["src_ip"] = packet.src_ip

    if packet.dst_ip != None:
        packet_dictionary["dst_ip"] = packet.dst_ip

    if packet.id != None:
        packet_dictionary["id"] = packet.id

    if packet.flags_mf != None:
        packet_dictionary["flags_mf"] = packet.flags_mf

    if packet.frag_offset != None:
        packet_dictionary["frag_offset"] = packet.frag_offset

    if packet.protocol != None:
        packet_dictionary["protocol"] = packet.protocol

    if packet.icmp_type != None:
        packet_dictionary["icmp_type"] = packet.icmp_type

    if packet.src_port != None:
        packet_dictionary["src_port"] = packet.src_port

    if packet.dst_port != None:
        packet_dictionary["dst_port"] = packet.dst_port

    if packet.app_protocol != None:
        packet_dictionary["app_protocol"] = packet.app_protocol

    packet_dictionary["hexa_frame"] = packet.hexa_frame

    if packet.sender_node != None:
        packet_dictionary["node"] = packet.sender_node

    if packet.sender_number_of_sent_packets != None:
        packet_dictionary["number_of_sent_packets"] = packet.sender_number_of_sent_packets

    if packet.communication_number_comm != None:
        packet_dictionary["number_comm"] = packet.communication_number_comm

    if packet.communication_src_comm != None:
        packet_dictionary["src_comm"] = packet.communication_src_comm

    if packet.communication_dst_comm != None:
        packet_dictionary["dst_comm"] = packet.communication_dst_comm

    if packet.communication_packets != None:
        packet_dictionary["packets"] = packet.communication_packets

    if packet.partial_communication_number_comm != None:
        packet_dictionary["number_comm"] = packet.partial_communication_number_comm

    if packet.partial_communication_packets != None:
        packet_dictionary["packets"] = packet.partial_communication_packets



#adding packet to packets field

    packets.append(packet_dictionary)

#FILTRE
#filter_udp(temp_array_udp,file_name)



dictionary["packets"] = packets




while True:
    switch = input()
    temp_p = switch[:2]
    temp_space = switch[2]
    temp_protocol = switch[3:]
    if temp_p == "-p" and temp_space == " ":
        if temp_protocol == "ARP":
            filter_arp(temp_array_arp, file_name)
        elif temp_protocol == "UDP":
            filter_udp(temp_array_udp,file_name)
        elif temp_protocol == "TCP":
            print_tcp(temp_array_tcp)
        else:
            print("Wrong input")
    elif switch == "break":
        break
    else:
        print("Wrong input")





#toto treba na konci odkomentovat !!!!!!!!!!!!!


#print("Topic/Item", "\t"*5, "Count")
#print("Source IPv4 Addresses", "\t"*2, count_values(Source_IPv4_Addresses))
max = 0
temp_id= ""
temp_array_output = []
for i in range(len(Source_IPv4_Addresses)):
    if Source_IPv4_Addresses[i].value > max:
        max = Source_IPv4_Addresses[i].value
        temp_id = Source_IPv4_Addresses[i].id
#    print(Source_IPv4_Addresses[i].id, "\t"*number_of_tabs(Source_IPv4_Addresses[i].id), Source_IPv4_Addresses[i].value)
    output = {"node": Source_IPv4_Addresses[i].id,
              "number_of_sent_packets": Source_IPv4_Addresses[i].value
    }
    temp_array_output.append(output)

dictionary["ipv4_senders"] = temp_array_output
dictionary["max_sent_packets_by"] = temp_id
#print("\nDestination IPv4 Addresses", "\t", count_values(Destination_IPv4_Addresses))
#for i in range(len(Destination_IPv4_Addresses)):
#    print(Destination_IPv4_Addresses[i].id, "\t"*number_of_tabs(Destination_IPv4_Addresses[i].id), Destination_IPv4_Addresses[i].value)



yaml = ruamel.yaml.YAML()
suborik = open("main_dictionary.yaml", "w")  # x=create, w=write, r=read
yaml.dump(dictionary, suborik)
suborik.close()