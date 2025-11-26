#!/usr/bin/env python3
"""
Basic AI Pentest Example
========================

This example demonstrates how to use the AI Pentest tool programmatically.
"""

import asyncio
import os
from ai_pentest.orchestrator import run_pentest
from ai_pentest.scanners import WebScanner, NetworkScanner, SSLScanner
from ai_pentest.ai import CursorAIClient
from ai_pentest.reports import ReportGenerator, PentestReport, Finding


async def full_scan_example():
    """Run a complete penetration test"""
    print("🔒 Running Full Penetration Test\n")
    
    # Run complete pentest
    report_path = await run_pentest(
        target="https://example.com",  # Replace with your target
        use_ai=True,  # Enable AI analysis
        report_format="html"
    )
    
    print(f"\n📄 Report saved to: {report_path}")


async def web_scan_example():
    """Run only web application scanning"""
    print("🌐 Running Web Application Scan\n")
    
    scanner = WebScanner(timeout=30.0)
    
    result = await scanner.scan(
        target="https://example.com",
        depth=2,
        check_xss=True,
        check_sqli=True,
        check_lfi=True,
        check_headers=True
    )
    
    print(f"\n✅ Scan Complete!")
    print(f"   URLs Crawled: {result.links_crawled}")
    print(f"   Forms Found: {result.forms_found}")
    print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
    
    for vuln in result.vulnerabilities:
        print(f"\n   [{vuln.severity.value.upper()}] {vuln.vuln_type.value}")
        print(f"   URL: {vuln.url}")
        if vuln.parameter:
            print(f"   Parameter: {vuln.parameter}")


async def network_scan_example():
    """Run network reconnaissance"""
    print("🔌 Running Network Scan\n")
    
    scanner = NetworkScanner()
    
    result = await scanner.scan(
        target="example.com",
        port_scan=True,
        port_range="quick",
        dns_enum=True,
        whois=True
    )
    
    print(f"\n✅ Scan Complete!")
    print(f"   Target: {result.target}")
    print(f"   IP: {result.network_info.ip_addresses}")
    
    if result.port_scan:
        print(f"   Open Ports: {len(result.port_scan.ports)}")
        for port in result.port_scan.ports[:5]:
            print(f"     - {port.port}/{port.service}")


async def ssl_scan_example():
    """Run SSL/TLS analysis"""
    print("🔐 Running SSL/TLS Analysis\n")
    
    scanner = SSLScanner()
    
    result = await scanner.scan(
        target="example.com",
        port=443
    )
    
    print(f"\n✅ Analysis Complete!")
    print(f"   Grade: {result.grade.value}")
    print(f"   TLS 1.3: {'Yes' if result.supports_tls_1_3 else 'No'}")
    print(f"   TLS 1.2: {'Yes' if result.supports_tls_1_2 else 'No'}")
    print(f"   Vulnerabilities: {len(result.vulnerabilities)}")


async def ai_analysis_example():
    """Use AI for vulnerability analysis"""
    print("🤖 Running AI Analysis\n")
    
    # Check for API key
    if not os.environ.get("CURSOR_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        print("⚠️  No API key found. Set CURSOR_API_KEY or ANTHROPIC_API_KEY")
        print("   The tool will run in offline mode with limited analysis.")
    
    async with CursorAIClient() as ai:
        # Analyze a hypothetical finding
        response = await ai.analyze(
            prompt="""
            Analyze this potential security finding:
            
            A reflected XSS vulnerability was found in the search parameter
            of the website. The payload <script>alert(1)</script> was
            reflected without encoding in the response.
            
            Provide:
            1. Severity assessment
            2. Potential impact
            3. Remediation steps
            """,
            context={
                "url": "https://example.com/search?q=test",
                "parameter": "q",
                "type": "Reflected XSS"
            }
        )
        
        print("AI Analysis:")
        print("-" * 50)
        print(response.content)


async def custom_report_example():
    """Generate a custom report"""
    print("📄 Generating Custom Report\n")
    
    # Create findings
    findings = [
        Finding(
            id="WEB-001",
            title="SQL Injection in Login Form",
            severity="critical",
            category="Web Application",
            description="SQL injection vulnerability found in the login form.",
            impact="Attackers can bypass authentication and access sensitive data.",
            remediation="Use parameterized queries instead of string concatenation.",
            url="https://example.com/login",
            parameter="username",
            cwe_id="CWE-89",
            cvss_score=9.8
        ),
        Finding(
            id="WEB-002",
            title="Missing Content-Security-Policy Header",
            severity="medium",
            category="Security Headers",
            description="The Content-Security-Policy header is not set.",
            impact="Increases risk of XSS attacks.",
            remediation="Add a strict Content-Security-Policy header.",
            cwe_id="CWE-693"
        ),
    ]
    
    # Create report
    report = PentestReport(
        title="Security Assessment - Example Corp",
        target="https://example.com",
        findings=findings,
        scope="Web application at example.com"
    )
    
    # Generate HTML report
    generator = ReportGenerator(output_dir="./reports")
    report_path = await generator.generate(
        report=report,
        format="html",
        use_ai=False  # Disable AI for this example
    )
    
    print(f"✅ Report generated: {report_path}")


async def main():
    """Run all examples"""
    print("=" * 60)
    print("   AI Pentest Tool - Examples")
    print("=" * 60)
    
    examples = [
        ("Web Scan", web_scan_example),
        ("Network Scan", network_scan_example),
        ("SSL Analysis", ssl_scan_example),
        ("AI Analysis", ai_analysis_example),
        ("Custom Report", custom_report_example),
    ]
    
    print("\nAvailable examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print("\nNote: Replace 'example.com' with your actual target.")
    print("Make sure you have authorization to test the target!\n")
    
    # Run a simple example
    # await web_scan_example()


if __name__ == "__main__":
    asyncio.run(main())
