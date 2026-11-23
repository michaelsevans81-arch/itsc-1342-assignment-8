
# Michael Evans - Assignment 8 Unit Tests
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'code')
))

from solution import aggregate_pcap_traffic

# Test 1: Protocol counts, unique IPs, and SYN packets
packets1 = [
    {"src": "192.168.1.1", "proto": "TCP", "syn_flag": True},
    {"src": "192.168.1.2", "proto": "UDP", "syn_flag": False},
    {"src": "192.168.1.1", "proto": "TCP", "syn_flag": True}
]

result1 = aggregate_pcap_traffic(packets1)

assert result1["protocols"] == {"TCP": 2, "UDP": 1}
assert result1["unique_sources"] == ["192.168.1.1", "192.168.1.2"]
assert result1["total_syn_packets"] == 2

# Test 2: Empty packet list
result2 = aggregate_pcap_traffic([])

assert result2["protocols"] == {}
assert result2["unique_sources"] == []
assert result2["total_syn_packets"] == 0

# Test 3: Unique IP sorting
packets3 = [
    {"src": "10.0.0.9", "proto": "TCP", "syn_flag": False},
    {"src": "10.0.0.1", "proto": "TCP", "syn_flag": True}
]

result3 = aggregate_pcap_traffic(packets3)

assert result3["unique_sources"] == ["10.0.0.1", "10.0.0.9"]
assert result3["protocols"] == {"TCP": 2}
assert result3["total_syn_packets"] == 1

print("ALL UNIT TESTS PASSED - ASSIGNMENT 8")
