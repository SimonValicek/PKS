import ruamel.yaml
temp_boolean = "false"
x = 0


def arp_add_to_array(array, packet):
    global temp_boolean
    global x
    if len(array) == 0:
        temp = str(packet.src_ip) + " to " + str(packet.dst_ip)
        array.append([])
        array[0].append([temp, packet.src_ip, packet.dst_ip, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.arp_opp, packet.hex_frame])
        return array
    elif len(array) != 0:
        var1 = str(packet.src_ip) + " to " + str(packet.dst_ip)
        var2 = str(packet.dst_ip) + " to " + str(packet.src_ip)

        if (array[x][0][0] == var1 or array[x][0][0] == var2) and temp_boolean == "false":
            array[x].append([var1, packet.src_ip, packet.dst_ip, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.arp_opp, packet.hex_frame])
            if packet.arp_opp == "REQUEST":
                temp_boolean = "false"
            if packet.arp_opp == "REPLY":
                temp_boolean = "true"
            return array


        array.append([[var1, packet.src_ip, packet.dst_ip, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.arp_opp, packet.hex_frame]])
        if packet.arp_opp == "REQUEST":
            temp_boolean = "false"
            x = x + 1
        if packet.arp_opp == "REPLY":
            temp_boolean = "true"
            x = x + 1
        return array

def switch_value():
    global temp_boolean
    if temp_boolean == "true":
        temp_boolean = "false"
    elif temp_boolean == "false":
        temp_boolean == "true"
    else:
        ('ERROR')



def filter_arp(array,name):
    if len(array) == 0:
        dictionary = {
            "name": "PKS2022/23",
            "pcap_name": name,
            "filter_name": "ARP",
        }
        yaml = ruamel.yaml.YAML()
        nieco = open("arp.yaml", "w")  # x=create, w=write, r=read
        yaml.dump(dictionary, nieco)
        nieco.close()
    else:
        complete = []
        partial = []
        first_line_complete = []
        first_line_partial = []

        dictionary = {
            "name": "PKS2022/23",
            "pcap_name": name,
            "filter_name": "ARP",
        }

        for x in range(len(array)):
            temp = len(array[x])
            if array[x][0][10] == "REQUEST" and array[x][temp-1][10] == "REPLY":
                complete.append(array[x])
            elif array[x][0][10] != "REQUEST" or array[x][temp-1][10] != "REPLY":
                partial.append(array[x])
            else:
                print("ERROR")

        #print('complete')

        for x in range(len(complete)):
            second_line_complete = []
            for y in range(len(complete[x])):
                single_packet = {   "frame_number": complete[x][y][3],
                                    "src_mac": complete[x][y][4],
                                    "dst_mac": complete[x][y][5],
                                    "len_frame_pcap": complete[x][y][6],
                                    "let_frame_medium": complete[x][y][7],
                                    "frame_type": complete[x][y][8],
                                    "ether_type": complete[x][y][9],
                                    "src_ip": complete[x][y][1],
                                    "dst_ip": complete[x][y][2],
                                    "arp_opcode": complete[x][y][10],
                                    "hexa_frame": complete[x][y][11]
                                 }
                #print("x: ", x, "y: ", y)
                #print(complete[x][y])
                second_line_complete.append(single_packet)
            packet_title = {"number_comm": x + 1,
                            "src_comm": complete[x][0][1],
                            "dst_comm": complete[x][0][2],
                            "packets": second_line_complete
                            }
            first_line_complete.append(packet_title)

        #print('partial')
        for x in range(len(partial)):
            second_line_partial = []
            for y in range(len(partial[x])):
                single_packet_p = {"frame_number": partial[x][y][3],
                                 "src_mac": partial[x][y][4],
                                 "dst_mac": partial[x][y][5],
                                 "len_frame_pcap": partial[x][y][6],
                                 "let_frame_medium": partial[x][y][7],
                                 "frame_type": partial[x][y][8],
                                 "ether_type": partial[x][y][9],
                                 "src_ip": partial[x][y][1],
                                 "dst_ip": partial[x][y][2],
                                 "arp_opcode": partial[x][y][10],
                                 "hexa_frame": partial[x][y][11]
                                 }
                second_line_partial.append((single_packet_p))
            packet_title_p = {"number_comm": x + 1,
                            "src_comm": partial[x][0][1],
                            "dst_comm": partial[x][0][2],
                            "packets": second_line_partial
                            }
            first_line_partial.append(packet_title_p)
            break


        dictionary["complete_comms"] = first_line_complete
        if len(first_line_partial) != 0:
            dictionary["partial_comms"] = first_line_partial
        yaml = ruamel.yaml.YAML()
        nic = open("arp.yaml", "w")  # x=create, w=write, r=read
        yaml.dump(dictionary, nic)
        nic.close()