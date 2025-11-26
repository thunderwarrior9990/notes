# 🔒 AI Pentest Tool

An AI-driven penetration testing tool with Cursor API integration and comprehensive report generation. Similar to HexStrike AI, this tool leverages AI to orchestrate security assessments, analyze tool outputs, and make intelligent decisions about next steps.

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

### 🧠 AI-Driven Penetration Testing Engine
- **Autonomous Decision Making** - AI Brain analyzes tool outputs and decides next steps
- **Full Methodology Coverage** - Reconnaissance → Enumeration → Vulnerability → Exploitation → Reporting
- **Attack Surface Mapping** - Automatically tracks assets, services, vulnerabilities, and credentials
- **Attack Planning** - AI generates prioritized attack paths with step-by-step guides
- **50+ Tool Integration** - Seamless integration with popular security tools

### 🎯 Scanning Capabilities
- **Network Reconnaissance** - DNS enumeration, port scanning, service detection, WHOIS lookup
- **Subdomain Enumeration** - Certificate transparency, DNS bruteforce, zone transfer attempts
- **Web Application Scanning** - XSS, SQL injection, LFI detection, security header analysis
- **SSL/TLS Analysis** - Certificate validation, protocol version checks, cipher suite analysis

### 🤖 AI-Powered Analysis
- **Intelligent Vulnerability Analysis** - AI explains findings and suggests exploitation approaches
- **Contextual Decision Making** - AI considers current attack surface when choosing tools
- **Risk Assessment** - Automatic severity classification with context
- **Remediation Guidance** - Detailed fix recommendations tailored to your environment
- **Report Generation** - AI-enhanced executive summaries and technical documentation

### 📊 Professional Reporting
- **HTML Reports** - Beautiful, interactive reports with severity breakdowns
- **PDF Export** - Print-ready professional documentation
- **JSON Output** - Machine-readable data for integration
- **Attack Surface Export** - Complete JSON export of discovered assets and vulnerabilities
- **Executive Summaries** - AI-generated summaries for non-technical stakeholders

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-pentest.git
cd ai-pentest

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .
```

### Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Add your API key:
```bash
# Edit .env and add your Cursor or Anthropic API key
CURSOR_API_KEY=your_api_key_here
# Or
ANTHROPIC_API_KEY=your_api_key_here
```

### Basic Usage

```bash
# 🚀 Run full AI-driven penetration test
ai-pentest pentest example.com

# Full security scan (classic mode)
ai-pentest scan example.com

# Web application scan only
ai-pentest scan https://example.com --type web

# Network reconnaissance
ai-pentest scan 192.168.1.1 --type network --ports full

# Subdomain enumeration
ai-pentest subdomains example.com

# SSL/TLS analysis
ai-pentest ssl example.com

# Generate PDF report
ai-pentest scan example.com --format pdf
```

## 🧠 AI-Driven Pentest Engine

The core feature is the AI-driven penetration testing engine that follows a complete methodology:

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI Pentest Engine                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Recon   │→ │  Enum    │→ │  Vuln    │→ │ Exploit  │→ Report│
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └─────────────┴──────┬──────┴─────────────┘               │
│                            │                                    │
│                     ┌──────▼──────┐                             │
│                     │  AI Brain   │                             │
│                     │  Analyzes   │                             │
│                     │  & Decides  │                             │
│                     └─────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Reconnaissance Phase**: Discovers assets, subdomains, services
   - AI analyzes results and recommends additional discovery tools
   
2. **Enumeration Phase**: Deep dives into discovered services
   - AI identifies interesting endpoints and suggests enumeration strategies

3. **Vulnerability Phase**: Identifies security issues
   - AI prioritizes findings and recommends validation approaches

4. **Exploitation Phase**: Validates and exploits vulnerabilities
   - AI generates attack plans with step-by-step guides

5. **Reporting Phase**: Generates comprehensive reports
   - AI writes executive summaries and recommendations

### Pentest Command

```bash
# Run full AI-driven pentest
ai-pentest pentest example.com

# Specify phases to run
ai-pentest pentest example.com --phases reconnaissance,enumeration,vulnerability

# Custom output and settings
ai-pentest pentest example.com \
  --output ./results \
  --max-iter 5 \
  --scope "api.example.com,admin.example.com"

# Manual mode (no auto decisions)
ai-pentest pentest example.com --manual

# Aggressive mode (faster, noisier)
ai-pentest pentest example.com --aggressive
```

### Attack Planning

```bash
# Generate attack plan from existing attack surface
ai-pentest attack-plan example.com --surface ./attack_surface.json

# The plan includes:
# - Prioritized attack paths
# - Step-by-step exploitation guides
# - Tool recommendations
# - Risk assessments
```

### Interactive Mode

```bash
# Start interactive session
ai-pentest interactive example.com

# Available commands in interactive mode:
#   status  - Show attack surface status
#   tools   - List available tools
#   run     - Run a specific tool
#   analyze - Get AI recommendations
#   vulns   - Show vulnerabilities
#   assets  - Show discovered assets
#   plan    - Generate attack plan
#   report  - Generate report
```

## 📖 Command Reference

### Main Scan Command

```bash
ai-pentest scan <target> [options]
```

| Option | Description |
|--------|-------------|
| `--type, -t` | Scan type: `full`, `web`, `network`, `recon`, `ssl` |
| `--ports, -p` | Port range: `quick`, `common`, `full`, or custom (e.g., `80,443,8080`) |
| `--output, -o` | Output directory for reports |
| `--format, -f` | Report format: `html`, `pdf`, `json` |
| `--no-ai` | Disable AI-enhanced analysis |
| `--verbose, -v` | Enable verbose output |

### Specialized Commands

```bash
# Web scanning with options
ai-pentest web https://example.com --depth 3 --no-xss

# Network scanning
ai-pentest network 192.168.1.0/24 --ports 1-1000

# Subdomain enumeration with custom wordlist
ai-pentest subdomains example.com --wordlist /path/to/wordlist.txt

# SSL analysis on custom port
ai-pentest ssl example.com --port 8443

# AI analysis of a finding
ai-pentest analyze "SQL injection found in login form"

# Generate report from JSON results
ai-pentest report scan_results.json --format pdf

# Show configuration
ai-pentest config --show
```

## 🔧 Python API

### AI-Driven Pentest Engine

```python
import asyncio
from ai_pentest import PentestEngine, EngineConfig, run_pentest

# Simple one-liner pentest
async def simple_pentest():
    result = await run_pentest(
        target="example.com",
        output_dir="./pentest_results",
        phases=["reconnaissance", "enumeration", "vulnerability", "reporting"],
        ai_enabled=True,
        auto_mode=True
    )
    
    print(f"Findings: {result.total_findings}")
    print(f"Vulnerabilities: {result.total_vulnerabilities}")
    print(f"Critical: {result.critical_count}")

asyncio.run(simple_pentest())

# Full configuration control
async def custom_pentest():
    config = EngineConfig(
        target="example.com",
        scope=["api.example.com", "admin.example.com"],
        output_dir="./pentest_results",
        
        # Phases
        phases_to_run=["reconnaissance", "enumeration", "vulnerability", "exploitation", "reporting"],
        
        # AI settings
        ai_enabled=True,
        auto_mode=True,
        max_iterations_per_phase=10,
        
        # Safety
        safe_mode=True,
        max_concurrent_tools=5
    )
    
    engine = PentestEngine(config)
    result = await engine.run()
    
    # Access detailed results
    for phase_name, phase_result in result.phase_results.items():
        print(f"{phase_name}: {phase_result.findings_count} findings")
    
    # Attack plan is auto-generated
    if result.attack_plan:
        print(f"Attack paths: {len(result.attack_plan.paths)}")

asyncio.run(custom_pentest())
```

### AI Brain and Attack Planning

```python
from ai_pentest import AIBrain, AttackPlanner, AttackSurface
from ai_pentest.engine.attack_surface import Asset, Vulnerability, AssetType, VulnSeverity

async def custom_planning():
    # Build attack surface
    attack_surface = AttackSurface("example.com")
    
    # Add discovered assets
    asset = Asset(
        id="web-1",
        name="www.example.com",
        asset_type=AssetType.WEB_APPLICATION,
        hostnames=["www.example.com"]
    )
    attack_surface.add_asset(asset)
    
    # Add vulnerability
    vuln = Vulnerability(
        id="VULN-001",
        title="SQL Injection",
        severity=VulnSeverity.CRITICAL,
        exploitable=True
    )
    attack_surface.add_vulnerability(vuln)
    
    # Get AI recommendations
    brain = AIBrain()
    await brain.initialize()
    
    decisions = await brain.decide_next_steps(
        attack_surface=attack_surface,
        current_phase="vulnerability"
    )
    
    for d in decisions:
        print(f"[{d.priority}] {d.tool}: {d.reasoning}")
    
    # Generate attack plan
    planner = AttackPlanner(brain)
    plan = await planner.generate_plan(attack_surface)
    
    print(f"Recommended path: {plan.recommended_path}")
    planner.display_plan(plan)
    
    await brain.close()

asyncio.run(custom_planning())
```

### Individual Scanner Usage

```python
from ai_pentest.scanners import WebScanner, NetworkScanner

async def web_scan():
    scanner = WebScanner()
    result = await scanner.scan(
        target="https://example.com",
        check_xss=True,
        check_sqli=True
    )
    
    for vuln in result.vulnerabilities:
        print(f"[{vuln.severity}] {vuln.vuln_type}: {vuln.url}")

asyncio.run(web_scan())
```

### AI Analysis

```python
from ai_pentest.ai import CursorAIClient

async def ai_analyze():
    async with CursorAIClient() as ai:
        response = await ai.analyze(
            prompt="Analyze this XSS vulnerability",
            context={"url": "https://example.com/search?q=<script>alert(1)</script>"}
        )
        print(response.content)

asyncio.run(ai_analyze())
```

## 📁 Project Structure

```
ai_pentest/
├── __init__.py              # Package initialization
├── cli.py                   # Command-line interface
├── config.py                # Configuration management
├── ai/
│   ├── __init__.py
│   ├── cursor_client.py     # AI API client (Cursor/Anthropic)
│   └── prompts.py           # AI prompts for analysis
├── engine/                  # 🧠 AI-Driven Pentest Engine
│   ├── __init__.py
│   ├── core.py              # Main PentestEngine orchestrator
│   ├── brain.py             # AI Brain - decision making core
│   ├── phases.py            # Pentest phases (recon, enum, vuln, exploit)
│   ├── planner.py           # Attack planning and path generation
│   └── attack_surface.py    # Attack surface data model
├── tools/                   # 50+ Security Tool Integrations
│   ├── __init__.py
│   ├── base.py              # Base ToolWrapper class
│   ├── manager.py           # Tool orchestration
│   ├── network/             # Nmap, Masscan, Subfinder, etc.
│   ├── web/                 # Nikto, SQLMap, Nuclei, etc.
│   ├── password/            # Hydra, John, Hashcat, etc.
│   ├── binary/              # Binwalk, Radare2, etc.
│   └── cloud/               # Prowler, Trivy, etc.
├── scanners/                # Built-in scanners
│   ├── __init__.py
│   ├── network.py           # Network reconnaissance
│   ├── web.py               # Web vulnerability scanning
│   ├── subdomain.py         # Subdomain enumeration
│   ├── ssl_scanner.py       # SSL/TLS analysis
│   └── ports.py             # Port scanning
├── reports/
│   ├── __init__.py
│   ├── generator.py         # Report generation
│   └── templates/           # HTML/PDF templates
└── utils/
    ├── __init__.py
    └── helpers.py           # Utility functions

examples/
├── basic_scan.py            # Basic scanning examples
└── full_pentest.py          # Full AI-driven pentest examples
```

## 🔐 Security Considerations

⚠️ **Important:** This tool is intended for authorized security testing only.

- **Always obtain proper authorization** before testing any system
- **Stay within scope** - only test systems you have permission to test
- **Use responsibly** - this tool can identify real vulnerabilities
- **Comply with laws** - unauthorized testing may be illegal in your jurisdiction

## 🛠️ Configuration

### config.yaml

```yaml
# API Configuration
cursor:
  api_key: ${CURSOR_API_KEY}
  model: "claude-3-5-sonnet-20241022"
  max_tokens: 4096

# Scanning Configuration
scanning:
  network:
    timeout: 30
    max_concurrent: 50
  web:
    timeout: 30
    user_agent: "AI-Pentest/1.0"
  subdomain:
    timeout: 10
    max_concurrent: 100

# Report Configuration
report:
  output_dir: "./reports"
  format: "html"
  include_evidence: true

# Safety Settings
safety:
  requests_per_second: 10
  respect_robots_txt: true
  max_crawl_depth: 3
```

## 🤝 API Integration

### Cursor.com Integration

The tool integrates with Cursor's API for AI-powered analysis. Set your API key:

```bash
export CURSOR_API_KEY=your_api_key
```

### Anthropic Direct Integration

Alternatively, use Anthropic's Claude API directly:

```bash
export ANTHROPIC_API_KEY=your_api_key
```

The tool will automatically detect and use the available API.

## 📊 Sample Report

The tool generates comprehensive reports including:

1. **Executive Summary** - High-level overview for stakeholders
2. **Findings Summary** - Severity breakdown with counts
3. **Detailed Findings** - Each vulnerability with:
   - Description
   - Impact analysis
   - Evidence/PoC
   - Remediation steps
   - CWE/CVE references
4. **Methodology** - Testing approach documentation
5. **Recommendations** - Prioritized remediation roadmap

## 🔧 Integrated Security Tools

The tool integrates with 50+ popular security tools across multiple categories:

### Network & Reconnaissance
| Tool | Binary | Description |
|------|--------|-------------|
| Nmap | `nmap` | Network exploration and security auditing |
| Masscan | `masscan` | Fast port scanner |
| Rustscan | `rustscan` | Modern port scanner with nmap integration |
| Amass | `amass` | Attack surface mapping and asset discovery |
| Subfinder | `subfinder` | Fast passive subdomain enumeration |
| Nuclei | `nuclei` | Template-based vulnerability scanner |
| Fierce | `fierce` | DNS reconnaissance |
| DNSEnum | `dnsenum` | DNS enumeration |
| AutoRecon | `autorecon` | Multi-threaded reconnaissance |
| TheHarvester | `theHarvester` | OSINT gathering |
| Responder | `responder` | LLMNR/NBT-NS/MDNS poisoner |
| NetExec | `nxc` | Network execution tool |
| Enum4linux | `enum4linux-ng` | Windows/Samba enumeration |

### Web Application Security
| Tool | Binary | Description |
|------|--------|-------------|
| Gobuster | `gobuster` | Directory/file brute forcing |
| Feroxbuster | `feroxbuster` | Recursive content discovery |
| Dirsearch | `dirsearch` | Web path discovery |
| Ffuf | `ffuf` | Fast web fuzzer |
| Dirb | `dirb` | Web content scanner |
| Httpx | `httpx` | HTTP probing toolkit |
| Katana | `katana` | Next-gen web crawler |
| Nikto | `nikto` | Web server scanner |
| SQLMap | `sqlmap` | SQL injection tool |
| WPScan | `wpscan` | WordPress security scanner |
| Arjun | `arjun` | HTTP parameter discovery |
| ParamSpider | `paramspider` | Parameter extraction |
| Dalfox | `dalfox` | XSS scanner |
| Wafw00f | `wafw00f` | WAF detection |

### Password & Authentication
| Tool | Binary | Description |
|------|--------|-------------|
| Hydra | `hydra` | Network authentication cracker |
| John | `john` | Password cracker |
| Hashcat | `hashcat` | Advanced password recovery |
| Medusa | `medusa` | Parallel authentication cracker |
| Patator | `patator` | Multi-purpose brute-forcer |
| CrackMapExec | `crackmapexec` | AD Swiss army knife |
| Evil-WinRM | `evil-winrm` | WinRM shell |
| Hash-Identifier | `hashid` | Hash type identification |

### Binary Analysis & Reverse Engineering
| Tool | Binary | Description |
|------|--------|-------------|
| GDB | `gdb` | GNU Debugger |
| Radare2 | `r2` | Reverse engineering framework |
| Binwalk | `binwalk` | Firmware analysis |
| Checksec | `checksec` | Binary security checker |
| Strings | `strings` | String extraction |
| Objdump | `objdump` | Object file analyzer |
| Volatility3 | `vol` | Memory forensics |
| Foremost | `foremost` | File carving |
| Steghide | `steghide` | Steganography tool |
| Exiftool | `exiftool` | Metadata analyzer |

### Cloud Security
| Tool | Binary | Description |
|------|--------|-------------|
| Prowler | `prowler` | AWS/Azure/GCP security |
| Scout Suite | `scout` | Multi-cloud security auditing |
| Trivy | `trivy` | Container vulnerability scanner |
| Kube-hunter | `kube-hunter` | Kubernetes penetration testing |
| Kube-bench | `kube-bench` | CIS Kubernetes Benchmark |
| Docker Bench | `docker-bench-security` | Docker CIS Benchmark |

### Using Integrated Tools

```bash
# Check which tools are installed
ai-pentest tools --check

# Run a specific tool
ai-pentest run-tool NmapScanner 192.168.1.1

# Run reconnaissance tools
ai-pentest recon example.com

# Run vulnerability scanning
ai-pentest vuln-scan https://example.com
```

### Tool Integration in Python

```python
from ai_pentest.tools import ToolManager, NmapScanner, NucleiScanner

# Use the tool manager
async def run_tools():
    manager = ToolManager(use_ai=True)
    
    # Run reconnaissance
    result = await manager.run_recon("example.com")
    
    # Run specific tools
    nmap_result = await manager.run_tool("NmapScanner", "192.168.1.1")
    nuclei_result = await manager.run_tool("NucleiScanner", "https://example.com")
    
    await manager.close()

# Use tools directly
async def direct_tool_usage():
    nmap = NmapScanner()
    result = await nmap.run("192.168.1.1", scan_type="comprehensive")
    
    for finding in result.findings:
        print(f"[{finding['severity']}] {finding['title']}")
```

## 🧪 Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest tests/ --cov=ai_pentest --cov-report=html
```

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Inspired by [HexStrike AI](https://hexstrike.com)
- Powered by [Anthropic Claude](https://anthropic.com)
- Built with [Typer](https://typer.tiangolo.com) and [Rich](https://rich.readthedocs.io)

## 📧 Support

For issues and feature requests, please open a GitHub issue.

---

**⚡ Made with AI-powered security in mind**
