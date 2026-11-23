
# Michael Evans - Assignment 8

def aggregate_pcap_traffic(packet_list):
    protocol_counts = {}
    source_ips = set()
    total_syn = 0

    for packet in packet_list:
        protocol = packet["proto"]

        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        source_ips.add(packet["src"])

        if packet["syn_flag"] is True:
            total_syn += 1

    return {
        "protocols": protocol_counts,
        "unique_sources": sorted(source_ips),
        "total_syn_packets": total_syn
    }
