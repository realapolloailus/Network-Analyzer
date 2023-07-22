import textwrap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import sniff
from datetime import datetime

# Main function for sniffing and later GUI deployment
def main():
    sniff(prn=handle_packet)

# All the code that reads in and parses important information
def handle_packet(packet):
    capture_time = packet.time
    formatted_time = datetime.fromtimestamp(capture_time).strftime('%Y-%m-%d %H:%M:%S.%f')
    if packet.haslayer(IP):
        dest_mac = packet.dst.upper()
        source_mac = packet.src.upper()
        ethernet_protocol = packet.type
        data = str(packet.payload)
        print('\nEthernet Frame: ')
        print('Capture Time: {}'.format(formatted_time))
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, source_mac, ethernet_protocol))

        if ethernet_protocol == 2048:
            ipv4 = packet[IP]
            version = ipv4.version
            header_length = ipv4.ihl * 4
            ttl = ipv4.ttl
            protocol = ipv4.proto
            source = ipv4.src
            target = ipv4.dst
            data = str(ipv4.payload)

            print('\tIPv4 Packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('\t\tProtocol: {}, Source Location: {}, Target Location: {}'.format(protocol, source, target))

            if protocol == 1:
                icmp = packet[ICMP]
                icmp_type = icmp.type
                code = icmp.code
                checksum = icmp.chksum
                data = str(icmp.payload)

                print('\t\tICMP Packet:')
                print('\t\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('\t\t\tData:')
                print(format_multiline('\t\t\t\t', data))
            elif protocol == 6:
                tcp = packet[TCP]
                source_port = tcp.sport
                dest_port = tcp.dport
                sequence = tcp.seq
                ack = tcp.ack
                flags = tcp.flags
                data = str(tcp.payload)

                print('\t\tTCP Segment:')
                print('\t\t\tSource Port: {}, Destination Port: {}'.format(source_port, dest_port))
                print('\t\t\tSequence: {}, Acknowledgment: {}'.format(sequence, ack))
                print('\t\t\tFlags: {}'.format(flags))
                print('\t\t\tData:')
                print(format_multiline('\t\t\t\t', data))
            elif protocol == 17:
                udp = packet[UDP]
                source_port = udp.sport
                dest_port = udp.dport
                length = udp.len
                data = str(udp.payload)

                print('\t\tUDP Segment:')
                print('\t\t\tSource Port: {}, Destination Port: {}, Segment Length: {}'.format(source_port, dest_port, length))
                print('\t\t\tData:')
                print(format_multiline('\t\t\t\t', data))
            else:
                print('\t\tData:')
                print(format_multiline('\t\t\t', data))
        else:
            print('\tData:')
            print(format_multiline('\t\t', data))

# Formats the data string
def format_multiline(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    elif string is None:
        return ''
    else:
        return prefix + string


main()
