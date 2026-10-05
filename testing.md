# NetGuard Testing & Network Verification Guide

## 1. Unit Testing

NetGuard includes a comprehensive C++ unit test suite in `tests/test_main.cpp`.

To run all unit tests:

```bash
make test
```

### Verified Test Cases:
1. **Rule Engine Priority Ordering**: Ensures rule with priority 10 overrides rule with priority 100.
2. **Subnet Mask Matching**: Validates `/32`, `/24`, `/16`, and `ANY (0.0.0.0/0)` CIDR evaluation.
3. **Port & Port Range Matching**: Validates individual ports and ranges (e.g., `1000-2000`).
4. **Protocol Discrimination**: Validates filtering for TCP, UDP, ICMP, and ANY.
5. **Rule Enable/Disable Toggling**: Ensures disabled rules allow packets to pass to lower-priority rules.
6. **Token & Argument Parsing**: Validates IP, Port, Protocol, and Action parsing.
7. **CSV Import/Export**: Verifies lossless rule serialization and deserialization.
8. **Netlink Struct Sizing**: Asserts struct boundaries, alignment, and message framing.

---

## 2. Live Kernel Netfilter Network Testing

### Test Case 1: Block SSH Destination Port 22
```bash
# Add Drop rule
sudo netguard add --id 101 --proto tcp --dport 22 --action drop --desc "Block SSH"

# Attempt connection
nc -zv -w 2 127.0.0.1 22
# Expected Result: Connection timed out / Dropped

# Check counter
sudo netguard stats
```

### Test Case 2: Block Web Traffic Port 80
```bash
sudo netguard add --id 102 --proto tcp --dport 80 --action drop --desc "Block HTTP"
curl -m 2 http://example.com
# Expected Result: curl: (28) Connection timed out
```

### Test Case 3: Block ICMP Ping
```bash
sudo netguard add --id 103 --proto icmp --action drop --desc "Block Ping"
ping -c 2 -W 1 127.0.0.1
# Expected Result: 100% packet loss
```

### Test Case 4: Restore Traffic (Disable Rule)
```bash
sudo netguard disable 103
ping -c 2 127.0.0.1
# Expected Result: 0% packet loss (Ping successful)
```
