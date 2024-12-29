import struct
from scapy.all import IP, UDP, Raw, sniff
from CovertChannelBase import CovertChannelBase
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        pass
    
    def handle_packet(self, packet,base):
        """
        Handles incoming UDP packets, extracts covert information from the payload, and stops sniffing if necessary. 
        Checks if the packet is a UDP packet with the correct source port.
        Extracts the first byte from the payload to determine the leap indicator (li).
        If the indicator is 3, sniffing stops, signaling the end of communication.
        Otherwise, it reconstructs bits from two successive packets and stores them.
        """
        if not packet.haslayer(UDP) or packet[UDP].sport != self.port_no:
            return
        
        first_byte = struct.unpack('!B', bytes(packet[UDP].payload)[:1])[0]
        li = (first_byte >> 6) & 0x03

        if li == base:
            self.stop_sniffing = True
        else:
            if self.second == 0:
                self.li_first = li
            else:
                combined_li = (self.li_first * base) + li
                bits = bin(combined_li)[2:].zfill(8)[-base:]
                self.received_bits.append(bits)
            self.second = 1 - self.second

    def build_ntp_packet(self, leap,base = 3):
        """
        Constructs an NTP (Network Time Protocol) packet with a custom leap indicator (li) value.
        Encodes the leap value in the first byte and pads the remaining packet with zeros to form a valid NTP packet.
        """
        first = (leap << 6) | (base << base) | base 
        packet = struct.pack('!B', first) + b'\x00' * 47
        return packet

    def transmit_ntp_packet(self, server_address, destination_port, packet):
        """
        Sends the crafted NTP packet to a specified server and port using UDP.
        Constructs an IP/UDP packet with the provided NTP payload and transmits it.
        """
        ip = IP(dst=server_address)
        udp = UDP(sport=destination_port, dport=destination_port)
        raw = Raw(load=packet)
        processed_pckt = ip / udp / raw
        CovertChannelBase.send(self, processed_pckt)
    

    def send(self, log_file_name, server_ip, port_no, chunk_length, min_max_length, base, binary, initial_value, the_end, one, zero,int_one):
        """
        Sends a binary message covertly through UDP packets by encoding the message into NTP packets.
        Generates a random binary message, splits it into chunks, and sends each chunk using the covert channel.
        If the message ends, sends a termination packet (li=3) to signal the end of communication.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_max_length, min_max_length)
        binary_message += the_end
        ntp_server = server_ip
        port = port_no
        chunk_size = chunk_length

        grouped = [binary_message[i:i + chunk_size] for i in range(zero, len(binary_message) - int_one, chunk_size)]
        if len(binary_message) % chunk_size == 1:
            grouped.append(binary_message[-1:])

        start_time = time.time()
        for group in grouped:
            if group == the_end:
                li = base
                packet = self.build_ntp_packet(li,base)
                self.transmit_ntp_packet(ntp_server, port, packet)
                end_time = time.time()
        
                time_elapsed = end_time - start_time
                covert_channel_capacity = min_max_length * base * base * base / time_elapsed
        
                #print(f'Covert Channel Capacity: {covert_channel_capacity:.2f} bits/second')
            else:
                group = one + group
                i = initial_value
                while i < len(group) - binary:
                    li_temp = group[i:i+base]
                    li = int(li_temp, binary) 
                    li_1 = li // base
                    li_2 = li % base
                    packet = self.build_ntp_packet(li_1,base)
                    self.transmit_ntp_packet(ntp_server, port, packet)

                    packet = self.build_ntp_packet(li_2,base)
                    self.transmit_ntp_packet(ntp_server, port, packet)
                    i += base


    def receive(self, port_no, log_file_name, chunk_length, base, binary, initial_value, zero, one):
        """
        Listens for incoming UDP packets on a specified port to receive covert messages.
        Captures packets, processes the payload to extract bits, and reconstructs the original message.
        Writes the reconstructed message to a log file.
        """
        self.received_bits = []
        self.second = initial_value
        self.li_first = initial_value
        self.stop_sniffing = False
        self.port_no = port_no 

        sniff_filter = f"udp port {port_no}"
        sniff(
            filter=sniff_filter,
            prn=lambda packet: self.handle_packet(packet, base), 
            stop_filter=lambda _: self.stop_sniffing
        )

        binary_str = ''.join(self.received_bits)
        chunk_size = chunk_length
        binary_groups = [binary_str[i:i + chunk_size] for i in range(zero, len(binary_str), chunk_size)]
        
        message = ""
        for group in binary_groups:
            if len(group) == (base*base) :
                bits = group[one:(base*base)] 
                message += chr(int(bits, binary))

        with open(log_file_name, 'w') as log_file:
            log_file.write(message)
