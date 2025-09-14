# Cybersecurity_Playground

https://claude.ai/public/artifacts/5acae03c-cf55-4648-8b1c-8f1800a780e8

<img width="1024" height="1024" alt="Gemini_Generated_Image_8nh6sv8nh6sv8nh6" src="https://github.com/user-attachments/assets/e88c327d-1629-4259-b0db-0516858e4382" />

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

Cybersecurity_Playground

End-to-end hands-on learning repo for cybersecurity — from fundamentals to advanced offensive & defensive labs.
This repository contains theory (docs), interactive notebooks (hands-on labs), safe simulators (Python), and a Streamlit playground to visualize and practice techniques such as network scanning, packet capture, MITM, spoofing, vulnerability assessment, and standards (CVE / CVSS / NIST / ISO).

⚠️ Safety & Legal: This project is for education and testing in isolated/lab environments only. Never run offensive tools (exploits, active scans, spoofing, malware) against systems you do not own or lack explicit permission to test. Read the docs/ and obey local laws and your organization’s policies.

Quick links

docs/ — theory and guided tutorials

notebooks/ — runnable Jupyter labs (Nmap, Wireshark, Metasploit, MITM, malware sandboxing, vulnerability scanning)

src/ — Python helpers & safe simulators (scanner, sniffer, MITM demo, spoofing tools)

streamlit_app/ — interactive learning web app (visual demos)

examples/ — sample PCAPs, scans, and config files

images/prompts/ — image generation prompts for holographic visuals

requirements.txt — suggested Python packages to install

Learning Roadmap (Beginner → Advanced)

Cybersecurity basics (docs/01_cybersecurity_basics.md)

Terminology, confidentiality/integrity/availability, attacker motivations, "hats".

Network fundamentals & scanning (docs/02_network_scanning.md)

IPs, ports, protocols, Nmap basics, safe scanning practices.

Traffic capture & analysis (docs/04_wire_shark.md)

Packet structure, filters, follow TCP stream, common indicators.

Kali Linux & tools (docs/03_kali_linux_tools.md)

Toolchain overview: Nmap, Netcat, Metasploit, Aircrack, John, etc.

Exploitation & Metasploit (docs/05_metasploit.md)

Safe, lab-only exploitation demos and post-exploitation basics.

Attacks: MITM, spoofing, malware (docs/07_spoofing_mitm.md, docs/08_malware_ransomware.md)

ARP spoofing, DNS spoofing, packet injection, sandboxing malware behaviors.

Vulnerability management & standards (docs/09_vulnerabilities.md, docs/10_security_standards.md)

CVE, CVSS scoring, vulnerability scanners (OpenVAS/Nessus), compliance frameworks.

Advanced topics & defensive practices (docs/11_advanced_topics.md)

Blue team techniques, IDS/IPS, honeypots, threat hunting and logging.

Quickstart — Setup (local lab)

Recommended: run in an isolated VM lab (no direct connection to production or Internet unless intentionally required).

Create a Python virtual environment:

python3 -m venv venv
source venv/bin/activate
pip install -U pip


Install the base requirements:

# example requirements (see requirements.txt)
pip install -r requirements.txt


Example requirements.txt (suggested):

jupyterlab
notebook
scapy
python-nmap
pandas
matplotlib
plotly
streamlit
requests
dnspython
pytest


Some labs/tools require external dependencies (Nmap binary, Metasploit, Wireshark). Check each notebook/docs for specific notes.

Launch Jupyter:

jupyter lab
# or
jupyter notebook


Run Streamlit app (optional):

cd streamlit_app
streamlit run app.py

Running Notebooks (safe mode)

Open notebooks/ in Jupyter.

Important: Before running a lab that uses live network operations (scanning, spoofing, MITM), ensure your environment is a contained lab VM / virtual network. Use the examples/ sample files for analysis if unsure.

Folder structure (summary)
Cybersecurity_Playground/
├── README.md
├── requirements.txt
├── LICENSE
├── docs/
├── notebooks/
├── src/
│   ├── scanner.py
│   ├── packet_sniffer.py
│   ├── metasploit_wrapper.py
│   ├── mitm_attack.py
│   ├── spoofing_tools.py
│   ├── malware_simulator.py
│   └── vuln_checker.py
├── streamlit_app/
├── tests/
├── examples/
└── images/

Module & Lab Highlights
src/scanner.py

Safe wrappers for python-nmap to run controlled port and host scans.

Use only against lab targets. Provide examples in notebooks/01_Network_Scanning.ipynb.

src/packet_sniffer.py

Scapy-based sniffing helper for parsing and saving PCAPs.

Visualize with Wireshark or notebooks.

src/metasploit_wrapper.py

Lightweight examples to interact with Metasploit RPC (lab-only). Requires Metasploit installed and configured.

src/mitm_attack.py & src/spoofing_tools.py

Educational demos (ARP spoofing, DNS spoofing) implemented for simulated networks and with clear safeguards. Always run these in isolated virtual networks.

src/malware_simulator.py

Non-malicious behavioral simulations that model ransomware-like file actions without real payloads—useful for detection and response labs.

src/vuln_checker.py

CVE lookups, CVSS scoring helpers, parsing vulnerability feeds (sample vuln DB included in examples/).

Holographic images & prompts

We included images/prompts/ with suggested prompts to generate holographic visuals (Gemini, Claude, DALL·E, or your image model). Example prompt:

"Create a futuristic holographic war room infographic showing network map, Wireshark packet trace, Metasploit exploit console, and hacker hats (white/black/blue) — neon blue palette, transparent layers, educational labels."


Use these prompts to produce visuals for docs and presentations.

Safety, Ethics & Legal

Only perform offensive actions on devices/networks you own or have explicit permission to test.

Maintain logs and obtain written authorization for penetration testing.

For malware labs, run in isolated sandbox VMs with no outbound network.

Standards & References

CVE, CVSS — vulnerability identification & scoring.

NIST SP 800 series — cybersecurity frameworks and guidelines.

ISO/IEC 27001 — information security management.

CEE (Common Event Expression) — logging normalization.

American standards & regional compliance info covered in docs/10_security_standards.md.

Contributing

Add labs, notebooks, or improved detection logic via PRs.

Add examples/ PCAPs and benign malware behavior logs for detection testing.

Add unit tests under tests/. Follow the project style and include documentation for new labs.

Example: How to add a new lab

Create a new notebook under notebooks/ named 08_New_Lab.ipynb.

Add code to import helpers from src/. Use package-style import: from src.scanner import Scanner.

Add instructions in docs/ and update README.md learning roadmap.

Add tests in tests/ to verify helper function outputs (do not execute network operations in CI).

License

This repository is provided for educational purposes. Choose a license (MIT recommended) and include it in LICENSE. See LICENSE file for details.
Key Features:
🛡️ 1. Kali Linux Tools Dashboard

Simulated tool status display (Nmap, Metasploit, Wireshark, etc.)
Mock terminal output showing typical Nmap scan results
Educational overview of penetration testing tools

📊 2. Wireshark Packet Analysis

Interactive packet viewer with filtering by protocol (TCP, UDP, ICMP)
Realistic packet data with timestamps, source/destination IPs
Protocol statistics and visual packet flow representation

🐛 3. Metasploit Framework Lab

Step-by-step exploit simulation walkthrough
Mock payload execution with educational safety notices
Simulated meterpreter session establishment

🔍 4. Port Scanning Demo

Interactive port scanner with start/stop functionality
Visual heatmap showing response times
Comprehensive port status overview (open/closed/filtered)

👁️ 5. MITM Attack Detection

Before/after traffic comparison
Toggleable detection system showing ARP spoofing indicators
Real-time security heuristics demonstration

📡 6. ARP Spoofing Simulation

Network topology visualization
ARP table status monitoring
Comprehensive mitigation strategies and detection methods

💀 7. Static Malware Analysis

File metadata analysis (entropy, hashes, size)
String extraction simulation showing suspicious API calls
Risk assessment with detailed analysis summary

⚠️ 8. Vulnerability Assessment

CVE database simulation with severity ratings
System inventory scanning
Prioritized remediation guidance

Educational Benefits:

Safe Learning Environment: All simulations use synthetic data
Interactive Elements: Buttons, filters, and real-time updates
Comprehensive Coverage: From network analysis to malware detection
Visual Learning: Heatmaps, color-coded statuses, and intuitive interfaces
Practical Context: Realistic scenarios and industry-standard tool interfaces


export default CyberSecDashboard;
