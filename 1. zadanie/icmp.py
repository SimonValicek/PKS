def icmp_add_to_array(array, packet):
    if len(array) == 0:
        temp = str(packet.src) + " to " + str(packet.dst)
        array.append([])
        array[0].append([temp, packet.src, packet.dst, packet.protocol, packet.flag, packet.order])
        return array
    elif len(array) != 0:
        var1 = str(packet.src) + " to " + str(packet.dst)
        var2 = str(packet.dst) + " to " + str(packet.src)
        for x in range(len(array)):
            if array[x][0][0] == var1 or array[x][0][0] == var2:
                array[x].append([var1, packet.src, packet.dst, packet.protocol, packet.flag, packet.order])
                return array

        array.append([[var1, packet.src, packet.dst, packet.protocol, packet.flag, packet.order]])
        return array

