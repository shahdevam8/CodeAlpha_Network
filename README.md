🐍 Network Packet Sniffer in PythonThis Python program captures network traffic in real-time and analyzes packets to display key details such as source and destination IPs, protocol type, and payload data. It uses the scapy library.
🚀 FeaturesCaptures live packets from the network interface
Displays:
Source IP
Destination IP
Protocol (TCP/UDP/ICMP)
Payload (if present)
Helps beginners understand how data flows through the network
🧰 RequirementsPython 3.x
scapy library
Run with admin/root privileges
Install dependencies:
pip install scapy🖥️ How to Runsudo python packet_sniffer.pyMake sure you run as administrator/root or the program will not have permission to capture packets.
📘 Example Output[+] Packet: TCP | 192.168.1.10 -> 93.184.216.34
Payload: GET /index.html HTTP/1.1
...🧠 LearningsBasics of networking protocols (TCP, UDP, IP, ICMP)
How packet headers and payloads are structured
Real-time monitoring and analysis
⚠️ NoteThis tool is for educational and ethical purposes only.
Unauthorized packet sniffing on networks you don’t own or have permission to monitor is illegal.
📂 File Structurepacket_sniffer.py
README.md👨‍💻 AuthorCreated by Devam Shah
Happy Sniffing! 📡
