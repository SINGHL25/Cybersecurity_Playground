
"""
Cybersecurity Playground - Interactive Learning Platform
Main Streamlit Application

A comprehensive cybersecurity education platform featuring hands-on labs,
simulations, and interactive demonstrations of security tools and concepts.
"""

import streamlit as st
import sys
import os
from datetime import datetime

# Add the current directory to the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    st.set_page_config(
        page_title="Cybersecurity Playground",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for cybersecurity theme
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72, #2a5298);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    
    .security-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border: 1px solid #4a5568;
    }
    
    .warning-box {
        background: linear-gradient(135deg, #ff7b7b 0%, #d63384 100%);
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
        border-left: 5px solid #dc3545;
    }
    
    .lab-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    
    .hacker-text {
        font-family: 'Courier New', monospace;
        color: #00ff41;
        background-color: #000;
        padding: 10px;
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Main header
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; margin: 0;">🛡️ Cybersecurity Playground</h1>
        <p style="color: #e2e8f0; margin: 0;">Master cybersecurity through hands-on labs and interactive simulations</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Warning disclaimer
    st.markdown("""
    <div class="warning-box">
        <h3 style="color: white; margin: 0;">⚠️ Educational Use Only</h3>
        <p style="color: white; margin: 10px 0 0 0;">
        This platform is designed for educational purposes and ethical security research. 
        All tools and techniques should only be used on systems you own or have explicit permission to test.
        Misuse of these tools may be illegal and unethical.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Introduction section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ## Welcome to the Cybersecurity Playground! 🚀
        
        This comprehensive platform provides hands-on experience with cybersecurity tools, 
        techniques, and concepts in a safe, educational environment. Whether you're a 
        beginner looking to learn the basics or an experienced professional wanting to 
        sharpen your skills, this playground offers something for everyone.
        
        ### 🎯 What You'll Learn:
        
        - **Reconnaissance & Scanning**: Network discovery and enumeration techniques
        - **Traffic Analysis**: Deep packet inspection with Wireshark-like tools
        - **Penetration Testing**: Exploitation frameworks and methodologies  
        - **Attack Simulations**: MITM, spoofing, and social engineering demos
        - **Malware Analysis**: Understanding threats in safe environments
        - **Vulnerability Assessment**: CVE analysis and security scanning
        - **Ethical Hacking**: White hat methodologies and responsible disclosure
        
        ### 📚 Interactive Learning Features:
        
        - **Hands-on Labs**: Practice with real tools in simulated environments
        - **Visual Demonstrations**: See attacks and defenses in action
        - **Progress Tracking**: Monitor your learning journey
        - **Safe Environment**: All simulations run in isolated sandboxes
        - **Real-world Scenarios**: Industry-relevant security challenges
        """)
    
    with col2:
        st.markdown("""
        <div class="security-card">
            <h3 style="color: white;">🔒 Security First</h3>
            <ul style="color: #e2e8f0;">
                <li>All labs run in isolated environments</li>
                <li>No actual systems are compromised</li>
                <li>Educational simulations only</li>
                <li>Ethical guidelines enforced</li>
                <li>Responsible disclosure practices</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="hacker-text">
        > System Status: SECURE<br>
        > Labs: OPERATIONAL<br>
        > Firewall: ACTIVE<br>
        > Monitoring: ENABLED<br>
        > Last Update: """ + datetime.now().strftime('%Y-%m-%d %H:%M') + """<br>
        </div>
        """, unsafe_allow_html=True)
    
    # Available Labs Overview
    st.markdown("---")
    st.markdown("## 🧪 Available Security Labs")
    
    # Lab cards in grid layout
    lab_col1, lab_col2, lab_col3 = st.columns(3)
    
    with lab_col1:
        st.markdown("""
        <div class="lab-card">
            <h4>🐧 Kali Linux Tools</h4>
            <p>Explore the arsenal of penetration testing tools available in Kali Linux. 
            Learn about each tool's purpose, usage, and real-world applications.</p>
            <strong>Tools Covered:</strong>
            <ul>
                <li>Nmap - Network Discovery</li>
                <li>Metasploit - Exploitation Framework</li>
                <li>Burp Suite - Web Application Testing</li>
                <li>John the Ripper - Password Cracking</li>
                <li>Aircrack-ng - Wireless Security</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="lab-card">
            <h4>🌐 MITM Attack Simulation</h4>
            <p>Understand Man-in-the-Middle attacks through safe simulations. 
            Learn detection and prevention techniques.</p>
            <strong>Concepts:</strong>
            <ul>
                <li>ARP Spoofing</li>
                <li>DNS Hijacking</li>
                <li>SSL Stripping</li>
                <li>Traffic Interception</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with lab_col2:
        st.markdown("""
        <div class="lab-card">
            <h4>📊 Wireshark Packet Analysis</h4>
            <p>Master packet analysis and network forensics using Wireshark-style 
            tools. Analyze network traffic and identify security issues.</p>
            <strong>Skills Developed:</strong>
            <ul>
                <li>Packet Capture Analysis</li>
                <li>Protocol Deep Dive</li>
                <li>Network Forensics</li>
                <li>Anomaly Detection</li>
                <li>Intrusion Analysis</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="lab-card">
            <h4>🎭 Spoofing Demonstrations</h4>
            <p>Learn various spoofing techniques and their countermeasures 
            through interactive demonstrations.</p>
            <strong>Types Covered:</strong>
            <ul>
                <li>IP Spoofing</li>
                <li>ARP Spoofing</li>
                <li>DNS Spoofing</li>
                <li>Email Spoofing</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with lab_col3:
        st.markdown("""
        <div class="lab-card">
            <h4>💥 Metasploit Framework</h4>
            <p>Hands-on experience with the world's most popular penetration 
            testing framework in controlled environments.</p>
            <strong>Modules Explored:</strong>
            <ul>
                <li>Auxiliary Scanners</li>
                <li>Exploit Modules</li>
                <li>Payload Generation</li>
                <li>Post-Exploitation</li>
                <li>Meterpreter Sessions</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="lab-card">
            <h4>🦠 Malware Analysis Lab</h4>
            <p>Safely analyze malware behavior and learn detection techniques 
            in isolated sandbox environments.</p>
            <strong>Analysis Types:</strong>
            <ul>
                <li>Static Analysis</li>
                <li>Dynamic Analysis</li>
                <li>Behavioral Analysis</li>
                <li>Ransomware Simulation</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Additional sections
    st.markdown("---")
    
    # Progress tracking and achievements
    progress_col1, progress_col2 = st.columns(2)
    
    with progress_col1:
        st.markdown("""
        ## 📈 Learning Path
        
        Follow our structured learning path to build comprehensive cybersecurity skills:
        
        ### 🥉 Beginner Level
        1. **Security Fundamentals** - Basic concepts and terminology
        2. **Network Scanning** - Discovery and enumeration techniques
        3. **Packet Analysis** - Understanding network communications
        
        ### 🥈 Intermediate Level
        4. **Penetration Testing** - Metasploit and exploitation techniques
        5. **Attack Simulations** - MITM and spoofing demonstrations
        6. **Malware Analysis** - Threat identification and analysis
        
        ### 🥇 Advanced Level
        7. **Vulnerability Assessment** - CVE analysis and scoring
        8. **Advanced Persistent Threats** - APT detection and response
        9. **Incident Response** - Digital forensics and recovery
        """)
    
    with progress_col2:
        st.markdown("""
        ## 🏆 Achievements & Certifications
        
        Track your progress and earn achievements as you complete labs:
        
        ### Available Badges:
        - 🔍 **Network Scanner** - Complete all scanning labs
        - 📦 **Packet Master** - Analyze 100+ packet captures
        - 🎯 **Exploit Expert** - Successfully run 10+ exploits
        - 🛡️ **Defense Specialist** - Implement 5+ countermeasures
        - 🔬 **Malware Hunter** - Analyze 10+ malware samples
        - 🚨 **Incident Responder** - Complete IR scenarios
        
        ### Certification Prep:
        This platform helps prepare for:
        - CEH (Certified Ethical Hacker)
        - CISSP (Certified Information Systems Security Professional)
        - Security+ (CompTIA Security+)
        - GCIH (GIAC Certified Incident Handler)
        - OSCP (Offensive Security Certified Professional)
        """)
    
    # Footer with navigation help
    st.markdown("---")
    st.markdown("""
    ## 🚀 Getting Started
    
    Ready to begin your cybersecurity journey? Here's how to get started:
    
    1. **Choose a Lab** - Select from the sidebar menu or click on a lab card above
    2. **Read the Theory** - Each lab includes background information and concepts
    3. **Follow the Exercises** - Step-by-step hands-on activities
    4. **Practice Skills** - Apply what you've learned in realistic scenarios
    5. **Track Progress** - Monitor your advancement through the curriculum
    
    ### 💡 Tips for Success:
    - Start with fundamentals if you're new to cybersecurity
    - Take notes and document your findings
    - Practice regularly to reinforce concepts
    - Join the community forums for discussion and help
    - Always follow ethical guidelines and legal requirements
    
    **Happy hacking (ethically)!** 🎉
    """)
    
    # Sidebar additional info
    with st.sidebar:
        st.markdown("""
        ## 🛡️ Security Resources
        
        ### Quick Links:
        - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
        - [CVE Database](https://cve.mitre.org/)
        - [Cybersecurity News](https://krebsonsecurity.com/)
        
        ### Emergency Contacts:
        - **CERT**: Computer Emergency Response Team
        - **FBI IC3**: Internet Crime Complaint Center
        - **Local Law Enforcement**: For criminal activity
        
        ### Legal Disclaimer:
        Use these tools only on systems you own or have explicit permission to test. 
        Unauthorized access is illegal and unethical.
        """)
        
        # Current lab status
        st.markdown("---")
        st.markdown("### 🔧 Lab Status")
        st.success("🟢 All systems operational")
        st.info("🔄 Last updated: " + datetime.now().strftime('%H:%M'))
        st.warning("⚠️ Remember: Educational use only!")

if __name__ == "__main__":
    main()
