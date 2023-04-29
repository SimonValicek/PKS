import ruamel.yaml

def udp_add_to_array(array, packet):
    if len(array) == 0 and packet.app_protocol == "TFTP":
        temp = str(packet.src_port) + " to " + str(packet.dst_port)
        array.append([])
        array[0].append([temp, packet.src_port, packet.dst_port, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.protocol, packet.src_ip, packet.dst_ip, packet.app_protocol, packet.hex_frame])
        return array
    elif len(array) != 0:
        var1 = str(packet.src_port) + " to " + str(packet.dst_port)
        var2 = str(packet.dst_port) + " to " + str(packet.src_port)
        var3 = str(packet.src_port) + " to 69"
        var4 = str(packet.dst_port) + " to 69"
        for x in range(len(array)):
            if array[x][0][0] == var1 or array[x][0][0] == var2 or array[x][0][0] == var3 or array[x][0][0] == var4:
                array[x].append([var1, packet.src_port, packet.dst_port, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.protocol, packet.src_ip, packet.dst_ip, packet.app_protocol, packet.hex_frame])
                return array

        if packet.app_protocol == "TFTP":
            array.append([[var1, packet.src_port, packet.dst_port, packet.frame_number, packet.src_mac, packet.dst_mac, packet.len_pcap, packet.len_medium, packet.frame_type, packet.ether_type, packet.protocol, packet.src_ip, packet.dst_ip, packet.app_protocol, packet.hex_frame]])
            return array
        else:
            return array
    else:
        return array


def filter_udp(array,name):
    if len(array) == 0:
        dictionary = {
            "name": "PKS2022/23",
            "pcap_name": name,
            "filter_name": "TFTP",
        }
        yaml = ruamel.yaml.YAML()
        nieco = open("arp.yaml", "w")  # x=create, w=write, r=read
        yaml.dump(dictionary, nieco)
        nieco.close()
    else:
        first_line = []

        dictionary = {
            "name": "PKS2022/23",
            "pcap_name": name,
            "filter_name": "TFTP",
        }
        for x in range(len(array)):
            second_line = []
            for y in range(len(array[x])):
                single_packet = {"frame_number": array[x][y][3],
                                 "src_mac": array[x][y][4],
                                 "dst_mac": array[x][y][5],
                                 "len_frame_pcap": array[x][y][6],
                                 "frame_type": array[x][y][8],
                                 "ether_type": array[x][y][9],
                                 "protocol": array[x][y][10],
                                 "src_ip": array[x][y][11],
                                 "dst_ip": array[x][y][12],
                                 }
                if array[x][y][13] != None:
                    single_packet["app_protocol"] = array[x][y][13]
                single_packet["hexa_frame"] = array[x][y][14]


                second_line.append(single_packet)
            packet_title = {"number_comm": x+1,
                            "src_comm": array[x][0][11],
                            "dst_comm": array[x][0][12],
                            "packets": second_line
                                }
            first_line.append(packet_title)


        dictionary["complete_comms"] = first_line
        yaml = ruamel.yaml.YAML()
        nic = open("udp.yaml", "w")  # x=create, w=write, r=read
        yaml.dump(dictionary, nic)
        nic.close()