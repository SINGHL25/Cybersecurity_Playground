import React, { useState, useEffect } from 'react';
import { Shield, Network, Bug, Search, Eye, Wifi, Skull, AlertTriangle, Play, Pause, Download, Filter, BarChart3, Globe, Lock, Unlock, Activity } from 'lucide-react';

const CyberSecDashboard = () => {
  const [activeTab, setActiveTab] = useState('kali');
  const [scanRunning, setScanRunning] = useState(false);
  const [selectedProtocol, setSelectedProtocol] = useState('all');
  const [exploitStep, setExploitStep] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [detectionEnabled, setDetectionEnabled] = useState(true);

  // Synthetic data
  const packetData = [
    { id: 1, time: '14:23:01.123', src: '192.168.1.100', dst: '192.168.1.1', protocol: 'TCP', length: 60, info: 'HTTP GET /index.html' },
    { id: 2, time: '14:23:01.145', src: '192.168.1.1', dst: '192.168.1.100', protocol: 'TCP', length: 1514, info: 'HTTP 200 OK' },
    { id: 3, time: '14:23:02.200', src: '192.168.1.105', dst: '8.8.8.8', protocol: 'UDP', length: 76, info: 'DNS Query google.com' },
    { id: 4, time: '14:23:02.220', src: '8.8.8.8', dst: '192.168.1.105', protocol: 'UDP', length: 92, info: 'DNS Response' },
    { id: 5, time: '14:23:03.100', src: '192.168.1.100', dst: '192.168.1.50', protocol: 'ICMP', length: 98, info: 'Echo Request' },
  ];

  const portScanData = [
    { port: 21, service: 'FTP', status: 'closed', response_time: 0 },
    { port: 22, service: 'SSH', status: 'open', response_time: 15 },
    { port: 23, service: 'Telnet', status: 'filtered', response_time: 1000 },
    { port: 25, service: 'SMTP', status: 'closed', response_time: 0 },
    { port: 53, service: 'DNS', status: 'open', response_time: 8 },
    { port: 80, service: 'HTTP', status: 'open', response_time: 12 },
    { port: 110, service: 'POP3', status: 'closed', response_time: 0 },
    { port: 143, service: 'IMAP', status: 'closed', response_time: 0 },
    { port: 443, service: 'HTTPS', status: 'open', response_time: 18 },
    { port: 993, service: 'IMAPS', status: 'closed', response_time: 0 },
  ];

  const vulnerabilities = [
    { cve: 'CVE-2023-1234', severity: 'HIGH', service: 'Apache 2.4.41', description: 'Buffer overflow in mod_rewrite', remediation: 'Update to Apache 2.4.54+' },
    { cve: 'CVE-2023-5678', severity: 'MEDIUM', service: 'OpenSSL 1.1.1k', description: 'Information disclosure', remediation: 'Update to OpenSSL 1.1.1w+' },
    { cve: 'CVE-2023-9012', severity: 'CRITICAL', service: 'Nginx 1.18.0', description: 'Remote code execution', remediation: 'Update to Nginx 1.22.1+' },
  ];

  const exploitSteps = [
    'Initial reconnaissance completed',
    'Target enumeration in progress...',
    'Vulnerability identified: CVE-2023-1234',
    'Payload generation complete',
    'Connection established',
    'Privilege escalation attempt',
    'Access granted - educational simulation only!'
  ];

  const malwareStrings = [
    'CreateFileA', 'WriteFile', 'GetProcAddress', 'LoadLibraryA',
    'RegOpenKeyExA', 'URLDownloadToFileA', 'WinExec', 'ShellExecuteA'
  ];

  useEffect(() => {
    let interval;
    if (scanRunning) {
      interval = setInterval(() => {
        setScanProgress(prev => prev >= 100 ? 100 : prev + 10);
      }, 500);
    }
    return () => clearInterval(interval);
  }, [scanRunning]);

  const filteredPackets = selectedProtocol === 'all' 
    ? packetData 
    : packetData.filter(packet => packet.protocol.toLowerCase() === selectedProtocol.toLowerCase());

  const KaliTools = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Shield className="text-red-500" />
        Kali Linux Tools Dashboard
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[
          { name: 'Nmap', desc: 'Network discovery and security auditing', icon: Network, status: 'Ready' },
          { name: 'Metasploit', desc: 'Penetration testing framework', icon: Bug, status: 'Ready' },
          { name: 'Wireshark', desc: 'Network protocol analyzer', icon: Activity, status: 'Ready' },
          { name: 'Burp Suite', desc: 'Web application security testing', icon: Globe, status: 'Ready' },
          { name: 'John the Ripper', desc: 'Password cracking tool', icon: Lock, status: 'Ready' },
          { name: 'Aircrack-ng', desc: 'Wireless network security', icon: Wifi, status: 'Ready' },
        ].map((tool, idx) => (
          <div key={idx} className="bg-gray-800 p-4 rounded border border-green-500">
            <div className="flex items-center gap-2 mb-2">
              <tool.icon className="text-green-400" size={20} />
              <span className="font-semibold text-green-400">{tool.name}</span>
            </div>
            <p className="text-gray-300 text-sm mb-2">{tool.desc}</p>
            <span className="inline-block px-2 py-1 bg-green-900 text-green-300 text-xs rounded">
              {tool.status}
            </span>
          </div>
        ))}
      </div>
      <div className="bg-black p-4 rounded border border-green-500 font-mono text-green-400">
        <div className="mb-2">┌──(kali㉿kali)-[~]</div>
        <div className="mb-2">└─$ nmap -sV 192.168.1.0/24</div>
        <div className="text-xs space-y-1">
          <div>Starting Nmap 7.94 ( https://nmap.org )</div>
          <div>Nmap scan report for 192.168.1.1</div>
          <div>Host is up (0.001s latency).</div>
          <div>PORT     STATE SERVICE VERSION</div>
          <div>22/tcp   open  ssh     OpenSSH 8.2p1</div>
          <div>80/tcp   open  http    Apache httpd 2.4.41</div>
          <div>443/tcp  open  ssl/http Apache httpd 2.4.41</div>
        </div>
      </div>
    </div>
  );

  const WiresharkAnalysis = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Activity className="text-blue-500" />
        Packet Analysis
      </h2>
      <div className="flex gap-4 items-center">
        <select 
          value={selectedProtocol} 
          onChange={(e) => setSelectedProtocol(e.target.value)}
          className="bg-gray-700 text-white p-2 rounded border border-blue-500"
        >
          <option value="all">All Protocols</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>
        <Filter className="text-blue-400" size={20} />
      </div>
      <div className="bg-gray-900 rounded border border-blue-500 overflow-hidden">
        <div className="bg-blue-900 p-2 font-mono text-sm">
          <div className="grid grid-cols-6 gap-4 font-semibold">
            <span>Time</span>
            <span>Source</span>
            <span>Destination</span>
            <span>Protocol</span>
            <span>Length</span>
            <span>Info</span>
          </div>
        </div>
        <div className="max-h-64 overflow-y-auto">
          {filteredPackets.map((packet, idx) => (
            <div key={packet.id} className={`grid grid-cols-6 gap-4 p-2 text-sm font-mono ${idx % 2 === 0 ? 'bg-gray-800' : 'bg-gray-750'}`}>
              <span className="text-yellow-400">{packet.time}</span>
              <span className="text-green-400">{packet.src}</span>
              <span className="text-red-400">{packet.dst}</span>
              <span className="text-blue-400">{packet.protocol}</span>
              <span>{packet.length}</span>
              <span className="text-gray-300">{packet.info}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded border border-blue-500">
        <h3 className="font-semibold mb-2">Protocol Statistics</h3>
        <div className="flex gap-4">
          {['TCP', 'UDP', 'ICMP'].map(proto => {
            const count = packetData.filter(p => p.protocol === proto).length;
            return (
              <div key={proto} className="text-center">
                <div className="text-2xl font-bold text-blue-400">{count}</div>
                <div className="text-sm text-gray-400">{proto}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  const MetasploitLab = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Bug className="text-red-500" />
        Metasploit Framework
      </h2>
      <div className="flex gap-2">
        <button 
          onClick={() => setExploitStep(prev => Math.min(prev + 1, exploitSteps.length - 1))}
          className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded flex items-center gap-2"
        >
          <Play size={16} />
          Next Step
        </button>
        <button 
          onClick={() => setExploitStep(0)}
          className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded"
        >
          Reset
        </button>
      </div>
      <div className="bg-black p-4 rounded border border-red-500 font-mono text-green-400">
        <div className="mb-2">msf6 > use exploit/multi/handler</div>
        <div className="mb-2">msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp</div>
        <div className="mb-2">msf6 exploit(multi/handler) > set LHOST 192.168.1.100</div>
        <div className="mb-2">msf6 exploit(multi/handler) > exploit</div>
        <div className="mt-4 space-y-1">
          {exploitSteps.slice(0, exploitStep + 1).map((step, idx) => (
            <div key={idx} className="text-yellow-400">
              [+] {step}
            </div>
          ))}
        </div>
      </div>
      <div className="bg-yellow-900 border border-yellow-500 p-4 rounded">
        <div className="flex items-center gap-2">
          <AlertTriangle className="text-yellow-400" size={20} />
          <span className="font-semibold text-yellow-400">Educational Notice</span>
        </div>
        <p className="text-yellow-200 mt-2">This is a simulated environment for learning purposes only. No actual exploitation is taking place.</p>
      </div>
    </div>
  );

  const ScanningDemo = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Search className="text-purple-500" />
        Port Scanning Simulation
      </h2>
      <div className="flex gap-2">
        <button 
          onClick={() => {
            setScanRunning(!scanRunning);
            if (!scanRunning) setScanProgress(0);
          }}
          className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded flex items-center gap-2"
        >
          {scanRunning ? <Pause size={16} /> : <Play size={16} />}
          {scanRunning ? 'Stop Scan' : 'Start Scan'}
        </button>
        {scanProgress > 0 && (
          <div className="flex-1 bg-gray-700 rounded-full p-1">
            <div className="bg-purple-500 h-2 rounded-full transition-all duration-500" style={{width: `${scanProgress}%`}}></div>
          </div>
        )}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 p-4 rounded border border-purple-500">
          <h3 className="font-semibold mb-2 flex items-center gap-2">
            <BarChart3 size={16} />
            Port Status Overview
          </h3>
          <div className="space-y-2">
            {portScanData.map(port => (
              <div key={port.port} className="flex justify-between items-center p-2 bg-gray-700 rounded">
                <span className="font-mono">{port.port}/{port.service}</span>
                <span className={`px-2 py-1 rounded text-xs ${
                  port.status === 'open' ? 'bg-green-900 text-green-300' :
                  port.status === 'filtered' ? 'bg-yellow-900 text-yellow-300' :
                  'bg-red-900 text-red-300'
                }`}>
                  {port.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-gray-800 p-4 rounded border border-purple-500">
          <h3 className="font-semibold mb-2">Response Time Heatmap</h3>
          <div className="grid grid-cols-5 gap-1">
            {portScanData.map(port => (
              <div key={port.port} className="aspect-square flex items-center justify-center rounded text-xs font-mono" style={{
                backgroundColor: port.response_time === 0 ? '#374151' :
                                port.response_time < 20 ? '#10b981' :
                                port.response_time < 100 ? '#f59e0b' : '#ef4444'
              }}>
                {port.port}
              </div>
            ))}
          </div>
          <div className="mt-2 text-xs text-gray-400">
            <div>Green: Fast (&lt;20ms) | Yellow: Moderate | Red: Slow | Gray: Closed</div>
          </div>
        </div>
      </div>
    </div>
  );

  const MITMDemo = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Eye className="text-orange-500" />
        MITM Attack Detection
      </h2>
      <div className="flex gap-2 items-center">
        <button 
          onClick={() => setDetectionEnabled(!detectionEnabled)}
          className={`px-4 py-2 rounded flex items-center gap-2 ${detectionEnabled ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}`}
        >
          {detectionEnabled ? <Lock size={16} /> : <Unlock size={16} />}
          Detection {detectionEnabled ? 'Enabled' : 'Disabled'}
        </button>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 p-4 rounded border border-orange-500">
          <h3 className="font-semibold mb-2">Normal Traffic</h3>
          <div className="font-mono text-sm space-y-1">
            <div>Client → Router: ARP Request (192.168.1.1)</div>
            <div>Router → Client: ARP Reply (MAC: aa:bb:cc:dd:ee:ff)</div>
            <div className="text-green-400">✓ MAC address consistent</div>
            <div className="text-green-400">✓ Response time normal (2ms)</div>
          </div>
        </div>
        <div className="bg-gray-800 p-4 rounded border border-orange-500">
          <h3 className="font-semibold mb-2">Suspicious Traffic</h3>
          <div className="font-mono text-sm space-y-1">
            <div>Client → Router: ARP Request (192.168.1.1)</div>
            <div>Attacker → Client: ARP Reply (MAC: 11:22:33:44:55:66)</div>
            {detectionEnabled && (
              <>
                <div className="text-red-400">⚠ MAC address changed!</div>
                <div className="text-red-400">⚠ Duplicate ARP reply detected</div>
                <div className="text-red-400">🚨 MITM attack detected!</div>
              </>
            )}
          </div>
        </div>
      </div>
      <div className="bg-orange-900 border border-orange-500 p-4 rounded">
        <h3 className="font-semibold text-orange-400 mb-2">Detection Heuristics</h3>
        <ul className="text-orange-200 space-y-1 text-sm">
          <li>• ARP table inconsistencies</li>
          <li>• Duplicate gateway MAC addresses</li>
          <li>• Unusual traffic patterns</li>
          <li>• Certificate changes</li>
        </ul>
      </div>
    </div>
  );

  const SpoofingDemo = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Wifi className="text-cyan-500" />
        ARP Spoofing Simulation
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 p-4 rounded border border-cyan-500">
          <h3 className="font-semibold mb-2">Network Topology</h3>
          <div className="font-mono text-sm space-y-2">
            <div>Router (192.168.1.1) - MAC: aa:bb:cc:dd:ee:ff</div>
            <div>Client (192.168.1.100) - MAC: 11:11:11:11:11:11</div>
            <div>Attacker (192.168.1.200) - MAC: 22:22:22:22:22:22</div>
          </div>
        </div>
        <div className="bg-gray-800 p-4 rounded border border-cyan-500">
          <h3 className="font-semibold mb-2">ARP Table Status</h3>
          <div className="font-mono text-sm space-y-1">
            <div className="text-red-400">192.168.1.1 → 22:22:22:22:22:22 (SPOOFED)</div>
            <div className="text-green-400">192.168.1.100 → 11:11:11:11:11:11 (NORMAL)</div>
            <div className="text-yellow-400">192.168.1.200 → 22:22:22:22:22:22 (ATTACKER)</div>
          </div>
        </div>
      </div>
      <div className="bg-cyan-900 border border-cyan-500 p-4 rounded">
        <h3 className="font-semibold text-cyan-400 mb-2">Mitigation Strategies</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-cyan-200 text-sm">
          <div>
            <h4 className="font-semibold">Prevention</h4>
            <ul className="space-y-1 mt-1">
              <li>• Static ARP entries</li>
              <li>• ARP monitoring tools</li>
              <li>• Network segmentation</li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold">Detection</h4>
            <ul className="space-y-1 mt-1">
              <li>• ARP table monitoring</li>
              <li>• Traffic analysis</li>
              <li>• DHCP snooping</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );

  const MalwareDemo = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Skull className="text-pink-500" />
        Static Malware Analysis
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 p-4 rounded border border-pink-500">
          <h3 className="font-semibold mb-2">Sample Metadata</h3>
          <div className="font-mono text-sm space-y-1">
            <div>Filename: sample.exe</div>
            <div>Size: 245,760 bytes</div>
            <div>MD5: d41d8cd98f00b204e9800998ecf8427e</div>
            <div>Entropy: 7.2 (High - Packed/Encrypted)</div>
            <div className="text-pink-400">⚠ Suspicious entropy level</div>
          </div>
        </div>
        <div className="bg-gray-800 p-4 rounded border border-pink-500">
          <h3 className="font-semibold mb-2">String Analysis</h3>
          <div className="max-h-32 overflow-y-auto font-mono text-xs space-y-1">
            {malwareStrings.map((str, idx) => (
              <div key={idx} className="text-pink-300">{str}</div>
            ))}
          </div>
          <div className="text-pink-400 text-sm mt-2">⚠ {malwareStrings.length} suspicious API calls found</div>
        </div>
      </div>
      <div className="bg-pink-900 border border-pink-500 p-4 rounded">
        <h3 className="font-semibold text-pink-400 mb-2">Analysis Summary</h3>
        <div className="text-pink-200 space-y-1 text-sm">
          <div>• High entropy suggests packing/encryption</div>
          <div>• Multiple file manipulation APIs detected</div>
          <div>• Registry modification capabilities present</div>
          <div>• Network communication functions identified</div>
          <div className="text-pink-400 font-semibold mt-2">Risk Level: HIGH - Further dynamic analysis recommended</div>
        </div>
      </div>
    </div>
  );

  const VulnerabilityChecker = () => (
    <div className="space-y-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <AlertTriangle className="text-yellow-500" />
        Vulnerability Assessment
      </h2>
      <div className="bg-gray-800 p-4 rounded border border-yellow-500">
        <h3 className="font-semibold mb-2">System Inventory</h3>
        <div className="font-mono text-sm space-y-1">
          <div>Apache HTTP Server 2.4.41</div>
          <div>OpenSSL 1.1.1k</div>
          <div>Nginx 1.18.0</div>
          <div>OpenSSH 8.2p1</div>
        </div>
      </div>
      <div className="space-y-3">
        {vulnerabilities.map((vuln, idx) => (
          <div key={idx} className={`p-4 rounded border ${
            vuln.severity === 'CRITICAL' ? 'bg-red-900 border-red-500' :
            vuln.severity === 'HIGH' ? 'bg-orange-900 border-orange-500' :
            'bg-yellow-900 border-yellow-500'
          }`}>
            <div className="flex justify-between items-start mb-2">
              <span className="font-semibold font-mono">{vuln.cve}</span>
              <span className={`px-2 py-1 rounded text-xs font-semibold ${
                vuln.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                vuln.severity === 'HIGH' ? 'bg-orange-600 text-white' :
                'bg-yellow-600 text-black'
              }`}>
                {vuln.severity}
              </span>
            </div>
            <div className="text-sm space-y-1">
              <div><strong>Affected:</strong> {vuln.service}</div>
              <div><strong>Description:</strong> {vuln.description}</div>
              <div><strong>Remediation:</strong> {vuln.remediation}</div>
            </div>
          </div>
        ))}
      </div>
      <div className="bg-green-900 border border-green-500 p-4 rounded">
        <h3 className="font-semibold text-green-400 mb-2">Remediation Priority</h3>
        <ol className="text-green-200 space-y-1 text-sm">
          <li>1. Address CRITICAL vulnerabilities immediately</li>
          <li>2. Plan HIGH severity updates within 48 hours</li>
          <li>3. Schedule MEDIUM severity fixes within 1 week</li>
          <li>4. Implement automated vulnerability scanning</li>
        </ol>
      </div>
    </div>
  );

  const tabs = [
    { id: 'kali', label: 'Kali Tools', icon: Shield, component: KaliTools },
    { id: 'wireshark', label: 'Packets', icon: Activity, component: WiresharkAnalysis },
    { id: 'metasploit', label: 'Metasploit', icon: Bug, component: MetasploitLab },
    { id: 'scanning', label: 'Port Scan', icon: Search, component: ScanningDemo },
    { id: 'mitm', label: 'MITM', icon: Eye, component: MITMDemo },
    { id: 'spoofing', label: 'Spoofing', icon: Wifi, component: SpoofingDemo },
    { id: 'malware', label: 'Malware', icon: Skull, component: MalwareDemo },
    { id: 'vuln', label: 'Vulnerabilities', icon: AlertTriangle, component: VulnerabilityChecker },
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component || KaliTools;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-3xl font-bold text-center mb-8 bg-gradient-to-r from-red-400 via-purple-400 to-blue-400 bg-clip-text text-transparent">
          Cybersecurity Learning Dashboard
        </h1>
        
        <div className="flex flex-wrap gap-2 mb-6 justify-center">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded flex items-center gap-2 transition-colors ${
                activeTab === tab.id 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <tab.icon size={16} />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="bg-gray-800 p-6 rounded-lg border border-gray-600">
          <ActiveComponent />
        </div>
        
        <div className="mt-6 text-center text-gray-400 text-sm">
          <p>Educational cybersecurity simulation - All data is synthetic and safe</p>
        </div>
      </div>
    </div>
  );
};

export default CyberSecDashboard;