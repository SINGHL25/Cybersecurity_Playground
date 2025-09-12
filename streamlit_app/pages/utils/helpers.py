
"""
Cybersecurity Playground - Utility Functions
Helper functions for cybersecurity simulations and educational tools
"""

import re
import socket
import struct
import random
import hashlib
import base64
import ipaddress
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union
import subprocess
import platform

def validate_ip_address(ip: str) -> bool:
    """Validate if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: Union[int, str]) -> bool:
    """Validate if the given port is valid (1-65535)."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))

def format_mac_address(mac: str) -> str:
    """Format MAC address to standard XX:XX:XX:XX:XX:XX format."""
    # Remove all separators and spaces
    clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac)
    
    if len(clean_mac) != 12:
        return ""
    
    # Format with colons
    formatted = ':'.join([clean_mac[i:i+2] for i in range(0, 12, 2)])
    return formatted.upper()

def generate_random_mac() -> str:
    """Generate a random MAC address."""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]).upper()

def ip_to_binary(ip: str) -> str:
    """Convert IP address to binary representation."""
    try:
        parts = ip.split('.')
        binary_parts = [format(int(part), '08b') for part in parts]
        return '.'.join(binary_parts)
    except:
        return ""

def calculate_network_range(network: str) -> Dict[str, str]:
    """Calculate network range information from CIDR notation."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        return {
            'network_address': str(net.network_address),
            'broadcast_address': str(net.broadcast_address),
            'netmask': str(net.netmask),
            'num_addresses': net.num_addresses,
            'first_host': str(list(net.hosts())[0]) if list(net.hosts()) else 'N/A',
            'last_host': str(list(net.hosts())[-1]) if list(net.hosts()) else 'N/A'
        }
    except:
        return {}

def port_scan_simulation(target_ip: str, port_range: Tuple[int, int]) -> Dict[str, List[int]]:
    """Simulate a port scan for educational purposes."""
    # This is a simulation - not actually scanning
    start_port, end_port = port_range
    
    # Simulate common open ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    for port in range(start_port, min(end_port + 1, start_port + 100)):  # Limit simulation
        if port in common_ports and random.random() > 0.3:
            open_ports.append(port)
        elif random.random() > 0.8:
            filtered_ports.append(port)
        else:
            closed_ports.append(port)
    
    return {
        'open': sorted(open_ports),
        'closed': sorted(closed_ports[:10]),  # Limit output
        'filtered': sorted(filtered_ports)
    }

def generate_packet_data(protocol: str = "TCP") -> Dict[str, any]:
    """Generate simulated packet data for analysis."""
    protocols = {
        'TCP': {'sport': random.randint(1024, 65535), 'dport': random.choice([80, 443, 22, 21])},
        'UDP': {'sport': random.randint(1024, 65535), 'dport': random.choice([53, 67, 68, 123])},
        'ICMP': {'type': random.choice([0, 3, 8, 11]), 'code': random.randint(0, 15)}
    }
    
    packet = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'src_ip': f"192.168.1.{random.randint(2, 254)}",
        'dst_ip': f"192.168.1.{random.randint(2, 254)}",
        'protocol': protocol,
        'length': random.randint(64, 1518),
        'ttl': random.randint(32, 128)
    }
    
    packet.update(protocols.get(protocol, {}))
    
    if protocol == 'TCP':
        packet['flags'] = random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH'])
        packet['seq'] = random.randint(1000000, 9999999)
        packet['ack'] = random.randint(1000000, 9999999)
    
    return packet

def analyze_packet_anomalies(packets: List[Dict]) -> Dict[str, List]:
    """Analyze packets for potential security anomalies."""
    anomalies = {
        'port_scans': [],
        'dos_attempts': [],
        'suspicious_traffic': [],
        'protocol_violations': []
    }
    
    if not packets:
        return anomalies
    
    # Analyze for port scanning patterns
    src_ports = {}
    for packet in packets:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in src_ports:
                src_ports[src_ip] = set()
            if 'dport' in packet:
                src_ports[src_ip].add(packet['dport'])
    
    for src_ip, ports in src_ports.items():
        if len(ports) > 10:  # Threshold for port scan detection
            anomalies['port_scans'].append({
                'src_ip': src_ip,
                'ports_scanned': len(ports),
                'severity': 'HIGH' if len(ports) > 50 else 'MEDIUM'
            })
    
    # Analyze for DoS patterns
    ip_counts = {}
    for packet in packets:
        src_ip = packet.get('src_ip')
        if src_ip:
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
    
    for src_ip, count in ip_counts.items():
        if count > 100:  # Threshold for DoS detection
            anomalies['dos_attempts'].append({
                'src_ip': src_ip,
                'packet_count': count,
                'severity': 'HIGH' if count > 500 else 'MEDIUM'
            })
    
    return anomalies

def generate_vulnerability_report(target: str) -> Dict[str, any]:
    """Generate a simulated vulnerability assessment report."""
    vulnerabilities = [
        {
            'id': 'CVE-2024-0001',
            'severity': 'HIGH',
            'score': 8.5,
            'title': 'Remote Code Execution in Web Service',
            'description': 'Buffer overflow vulnerability allows remote code execution'
        },
        {
            'id': 'CVE-2024-0002', 
            'severity': 'MEDIUM',
            'score': 6.2,
            'title': 'SQL Injection in Login Form',
            'description': 'Input validation bypass allows SQL injection attacks'
        },
        {
            'id': 'CVE-2024-0003',
            'severity': 'LOW',
            'score': 3.1,
            'title': 'Information Disclosure',
            'description': 'Server headers reveal sensitive version information'
        }
    ]
    
    # Simulate random selection of vulnerabilities
    selected_vulns = random.sample(vulnerabilities, random.randint(1, len(vulnerabilities)))
    
    report = {
        'target': target,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_vulnerabilities': len(selected_vulns),
        'high_risk': len([v for v in selected_vulns if v['severity'] == 'HIGH']),
        'medium_risk': len([v for v in selected_vulns if v['severity'] == 'MEDIUM']),
        'low_risk': len([v for v in selected_vulns if v['severity'] == 'LOW']),
        'vulnerabilities': selected_vulns,
        'recommendations': [
            'Apply security patches immediately for high-risk vulnerabilities',
            'Implement input validation and sanitization',
            'Configure secure server headers',
            'Regular vulnerability assessments recommended'
        ]
    }
    
    return report

def simulate_malware_behavior() -> Dict[str, any]:
    """Simulate malware behavior for educational analysis."""
    malware_types = [
        {
            'type': 'Trojan',
            'behaviors': ['Creates backdoor', 'Steals credentials', 'Downloads additional payloads'],
            'network_activity': ['Connects to C&C server', 'Exfiltrates data'],
            'file_operations': ['Creates hidden files', 'Modifies registry keys']
        },
        {
            'type': 'Ransomware',
            'behaviors': ['Encrypts user files', 'Displays ransom note', 'Deletes shadow copies'],
            'network_activity': ['Contacts payment server', 'Downloads encryption keys'],
            'file_operations': ['Encrypts documents', 'Creates ransom note files']
        },
        {
            'type': 'Spyware',
            'behaviors': ['Logs keystrokes', 'Takes screenshots', 'Records audio'],
            'network_activity': ['Sends data to remote server', 'Downloads updates'],
            'file_operations': ['Creates log files', 'Installs browser extensions']
        }
    ]
    
    selected_malware = random.choice(malware_types)
    
    simulation = {
        'malware_type': selected_malware['type'],
        'detection_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'risk_level': random.choice(['HIGH', 'CRITICAL']),
        'behaviors_observed': selected_malware['behaviors'],
        'network_indicators': selected_malware['network_activity'],
        'file_indicators': selected_malware['file_operations'],
        'iocs': {  # Indicators of Compromise
            'file_hashes': [generate_fake_hash('md5') for _ in range(3)],
            'ip_addresses': [generate_fake_ip() for _ in range(2)],
            'domains': [f"malicious{i}.example.com" for i in range(2)]
        },
        'mitigation_steps': [
            'Isolate affected systems immediately',
            'Run full system antivirus scan',
            'Check for lateral movement',
            'Update security signatures',
            'Monitor network traffic for IoCs'
        ]
    }
    
    return simulation

def generate_fake_hash(hash_type: str = 'md5') -> str:
    """Generate a fake hash for educational purposes."""
    if hash_type.lower() == 'md5':
        return ''.join([random.choice('0123456789abcdef') for _ in range(32)])
    elif hash_type.lower() == 'sha1':
        return ''.join([random.choice('0123456789abcdef') for _ in range(40)])
    elif hash_type.lower() == 'sha256':
        return ''.join([random.choice('0123456789abcdef') for _ in range(64)])
    else:
        return ''.join([random.choice('0123456789abcdef') for _ in range(32)])

def generate_fake_ip() -> str:
    """Generate a fake IP address for educational purposes."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def create_attack_timeline(attack_type: str) -> List[Dict[str, str]]:
    """Create a timeline of attack events for educational purposes."""
    timelines = {
        'APT': [
            {'time': '2024-01-01 09:00:00', 'event': 'Initial spear phishing email sent', 'stage': 'Initial Access'},
            {'time': '2024-01-01 09:15:00', 'event': 'User clicks malicious link', 'stage': 'Execution'},
            {'time': '2024-01-01 09:16:00', 'event': 'Malware payload downloaded', 'stage': 'Defense Evasion'},
            {'time': '2024-01-01 09:20:00', 'event': 'Persistence mechanism established', 'stage': 'Persistence'},
            {'time': '2024-01-01 10:30:00', 'event': 'Privilege escalation attempted', 'stage': 'Privilege Escalation'},
            {'time': '2024-01-01 11:00:00', 'event': 'Lateral movement to domain controller', 'stage': 'Lateral Movement'},
            {'time': '2024-01-01 14:00:00', 'event': 'Data discovery and collection', 'stage': 'Collection'},
            {'time': '2024-01-02 02:00:00', 'event': 'Data exfiltration begins', 'stage': 'Exfiltration'}
        ],
        'Ransomware': [
            {'time': '2024-01-01 08:30:00', 'event': 'Malicious email attachment opened', 'stage': 'Initial Access'},
            {'time': '2024-01-01 08:31:00', 'event': 'Ransomware payload executed', 'stage': 'Execution'},
            {'time': '2024-01-01 08:32:00', 'event': 'Shadow copies deleted', 'stage': 'Impact'},
            {'time': '2024-01-01 08:35:00', 'event': 'File encryption begins', 'stage': 'Impact'},
            {'time': '2024-01-01 09:15:00', 'event': 'Encryption completed', 'stage': 'Impact'},
            {'time': '2024-01-01 09:16:00', 'event': 'Ransom note displayed', 'stage': 'Impact'}
        ]
    }
    
    return timelines.get(attack_type, [])

def calculate_risk_score(vulnerabilities: List[Dict]) -> Dict[str, float]:
    """Calculate overall risk score based on vulnerabilities."""
    if not vulnerabilities:
        return {'score': 0.0, 'level': 'LOW'}
    
    total_score = sum(vuln.get('score', 0) for vuln in vulnerabilities)
    avg_score = total_score / len(vulnerabilities)
    
    # Adjust for quantity
    quantity_multiplier = min(1 + (len(vulnerabilities) - 1) * 0.1, 2.0)
    final_score = min(avg_score * quantity_multiplier, 10.0)
    
    if final_score >= 9.0:
        level = 'CRITICAL'
    elif final_score >= 7.0:
        level = 'HIGH'
    elif final_score >= 4.0:
        level = 'MEDIUM'
    else:
        level = 'LOW'
    
    return {
        'score': round(final_score, 1),
        'level': level,
        'total_vulnerabilities': len(vulnerabilities),
        'average_cvss': round(avg_score, 1)
    }

def generate_security_recommendations(
