# Cybersecurity_Playground
```PLAIN TEXT
Cybersecurity_Playground/
│
├── README.md                 # Project overview, learning roadmap, setup guide
├── requirements.txt          # Python dependencies for labs (scapy, nmap, etc.)
├── LICENSE                   # MIT or Apache License
│
├── docs/                     # Detailed tutorials & theory
│   ├── 01_cybersecurity_basics.md
│   ├── 02_network_scanning.md
│   ├── 03_kali_linux_tools.md
│   ├── 04_wire_shark.md
│   ├── 05_metasploit.md
│   ├── 06_hacker_hats.md            # White, Black, Blue, Red hats explained
│   ├── 07_spoofing_mitm.md
│   ├── 08_malware_ransomware.md
│   ├── 09_vulnerabilities.md
│   ├── 10_security_standards.md     # NIST, ISO, CVE, CVSS, CEE, American standards
│   └── 11_advanced_topics.md
│
├── notebooks/                # Jupyter notebooks for hands-on labs
│   ├── 01_Network_Scanning.ipynb       # Nmap, port scanning, IP scans
│   ├── 02_Wireshark_Analysis.ipynb     # Packet capture and analysis
│   ├── 03_Metasploit_Attacks.ipynb     # Exploit framework demos
│   ├── 04_MITM_Simulation.ipynb        # Man-in-the-Middle lab
│   ├── 05_Spoofing_Demo.ipynb          # ARP/DNS/IP spoofing
│   ├── 06_Malware_Ransomware.ipynb     # Behavioral analysis (safe sandbox demo)
│   └── 07_Vulnerability_Scanning.ipynb # Nessus, OpenVAS, CVE/CVSS labs
│
├── src/                      # Core Python modules for simulations
│   ├── __init__.py
│   ├── scanner.py            # Port, IP, network scanner
│   ├── packet_sniffer.py     # Wireshark-like sniffer (scapy based)
│   ├── metasploit_wrapper.py # Connect with Metasploit RPC
│   ├── mitm_attack.py        # MITM demo with scapy
│   ├── spoofing_tools.py     # ARP, DNS, IP spoof simulations
│   ├── malware_simulator.py  # Simple safe malware behavior demo
│   └── vuln_checker.py       # CVE & CVSS lookup, vulnerability scanner
│
├── streamlit_app/            # Interactive dashboards & labs
│   ├── app.py
│   ├── pages/
│   │   ├── 1_Kali_Linux_Tools.py
│   │   ├── 2_Wireshark_Packets.py
│   │   ├── 3_Metasploit_Lab.py
│   │   ├── 4_Scanning_Demo.py
│   │   ├── 5_MITM_Attack.py
│   │   ├── 6_Spoofing_Simulation.py
│   │   ├── 7_Malware_Demo.py
│   │   └── 8_Vulnerability_Checker.py
│   └── utils/
│       └── helpers.py
│
├── tests/                    # Unit tests
│   ├── test_scanner.py
│   ├── test_packet_sniffer.py
│   ├── test_metasploit_wrapper.py
│   ├── test_mitm_attack.py
│   ├── test_spoofing_tools.py
│   ├── test_malware_simulator.py
│   └── test_vuln_checker.py
│
├── examples/                 # Sample datasets & configs
│   ├── sample_packets.pcap
│   ├── nmap_scan_results.xml
│   ├── spoofing_targets.json
│   ├── malware_samples.yaml
│   └── vuln_database.csv
│
└── images/                   # Visual resources (holographic style)
    ├── prompts/
    │   ├── cyber_overview_prompt.txt
    │   ├── wireshark_prompt.txt
    │   ├── metasploit_prompt.txt
    │   ├── hacker_hats_prompt.txt
    │   ├── mitm_prompt.txt
    │   └── ransomware_prompt.txt
    └── generated/
        └── README.md




```
