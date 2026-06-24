#!/usr/bin/env python3
"""
ZumrutAutomation - Report Engine
Multi-format security assessment report generator with compliance mapping.
"""

import json
import logging
import hashlib
import os
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from enum import Enum
from pathlib import Path
import html
import uuid

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('ReportEngine')


class ReportFormat(Enum):
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    TEXT = "text"
    EXECUTIVE = "executive"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ComplianceFramework(Enum):
    SOC2 = "soc2"
    HIPAA = "hipaa"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    GDPR = "gdpr"


@dataclass
class Finding:
    """Individual security finding."""
    finding_id: str
    title: str
    severity: str
    category: str
    description: str
    target: str
    evidence: str
    remediation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    compliance_mappings: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    validated: bool = False


@dataclass
class MissionSummary:
    """Mission execution summary."""
    mission_id: str
    client_name: str
    start_time: str
    end_time: str
    duration_seconds: float
    targets_scanned: int
    modules_executed: List[str]
    total_findings: int
    findings_by_severity: Dict[str, int]
    risk_score: float
    scope_hash: str


@dataclass
class ComplianceStatus:
    """Compliance framework status."""
    framework: str
    controls_tested: int
    controls_passed: int
    controls_failed: int
    compliance_percentage: float
    failed_controls: List[Dict[str, str]]


@dataclass
class Report:
    """Complete security assessment report."""
    report_id: str
    generated_at: str
    report_version: str
    mission_summary: MissionSummary
    findings: List[Finding]
    compliance_status: List[ComplianceStatus]
    executive_summary: str
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    checksum: str = ""


class ComplianceMapper:
    """Maps findings to compliance framework controls."""
    
    CONTROL_MAPPINGS = {
        ComplianceFramework.SOC2: {
            "ssl_tls": ["CC6.1", "CC6.7"],
            "authentication": ["CC6.1", "CC6.2", "CC6.3"],
            "access_control": ["CC6.1", "CC6.2", "CC6.3"],
            "encryption": ["CC6.1", "CC6.7"],
            "logging": ["CC7.1", "CC7.2"],
            "xss": ["CC6.1", "CC7.1"],
            "injection": ["CC6.1", "CC7.1"],
            "security_headers": ["CC6.1", "CC6.6"],
            "open_ports": ["CC6.1", "CC6.6", "CC6.7"],
            "information_disclosure": ["CC6.1", "CC6.5"],
        },
        ComplianceFramework.HIPAA: {
            "ssl_tls": ["164.312(e)(1)", "164.312(e)(2)(ii)"],
            "authentication": ["164.312(d)", "164.312(a)(1)"],
            "access_control": ["164.312(a)(1)", "164.312(a)(2)(i)"],
            "encryption": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
            "logging": ["164.312(b)", "164.308(a)(1)(ii)(D)"],
            "xss": ["164.312(c)(1)"],
            "injection": ["164.312(c)(1)"],
            "security_headers": ["164.312(c)(1)", "164.312(e)(1)"],
            "open_ports": ["164.312(e)(1)"],
            "information_disclosure": ["164.312(e)(1)", "164.502"],
        },
        ComplianceFramework.NIST: {
            "ssl_tls": ["SC-8", "SC-13", "SC-23"],
            "authentication": ["IA-2", "IA-5", "IA-8"],
            "access_control": ["AC-2", "AC-3", "AC-6"],
            "encryption": ["SC-8", "SC-13", "SC-28"],
            "logging": ["AU-2", "AU-3", "AU-6"],
            "xss": ["SI-10", "SI-11"],
            "injection": ["SI-10", "SI-16"],
            "security_headers": ["SC-8", "SI-10"],
            "open_ports": ["CM-7", "SC-7"],
            "information_disclosure": ["SC-8", "SI-11"],
        },
        ComplianceFramework.PCI_DSS: {
            "ssl_tls": ["2.2.3", "4.1"],
            "authentication": ["8.1", "8.2", "8.3"],
            "access_control": ["7.1", "7.2"],
            "encryption": ["3.4", "4.1"],
            "logging": ["10.1", "10.2", "10.3"],
            "xss": ["6.5.7"],
            "injection": ["6.5.1"],
            "security_headers": ["6.5.10"],
            "open_ports": ["1.1.6", "2.2.2"],
            "information_disclosure": ["3.4", "6.5.8"],
        },
    }
    
    @classmethod
    def get_controls(cls, framework: ComplianceFramework, category: str) -> List[str]:
        """Get compliance controls for a finding category."""
        category_lower = category.lower().replace(" ", "_").replace("-", "_")
        framework_mappings = cls.CONTROL_MAPPINGS.get(framework, {})
        
        for key, controls in framework_mappings.items():
            if key in category_lower or category_lower in key:
                return controls
        
        return []
    
    @classmethod
    def map_finding(cls, finding: Finding, frameworks: List[ComplianceFramework]) -> List[str]:
        """Map a finding to all applicable compliance controls."""
        all_controls = []
        for framework in frameworks:
            controls = cls.get_controls(framework, finding.category)
            for control in controls:
                all_controls.append(f"{framework.value.upper()}:{control}")
        return all_controls


class ReportEngine:
    """Enterprise report generation engine."""
    
    def __init__(self, output_dir: str = "/var/lib/platform/reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.compliance_frameworks = [
            ComplianceFramework.SOC2,
            ComplianceFramework.HIPAA,
            ComplianceFramework.NIST,
            ComplianceFramework.PCI_DSS,
        ]
        logger.info(f"ReportEngine initialized. Output: {self.output_dir}")
    
    def generate_report(
        self,
        mission_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        formats: List[ReportFormat] = None
    ) -> Dict[str, str]:
        """Generate reports in specified formats."""
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.MARKDOWN]
        
        report = self._build_report(mission_data, findings_data)
        
        generated_files = {}
        for fmt in formats:
            try:
                filepath = self._render_report(report, fmt)
                generated_files[fmt.value] = str(filepath)
                logger.info(f"Generated {fmt.value} report: {filepath}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt.value} report: {e}")
        
        return generated_files
    
    def _build_report(
        self,
        mission_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]]
    ) -> Report:
        """Build complete report structure."""
        findings = self._process_findings(findings_data)
        
        mission_summary = MissionSummary(
            mission_id=mission_data.get("mission_id", str(uuid.uuid4())),
            client_name=mission_data.get("client_name", "Unknown"),
            start_time=mission_data.get("start_time", datetime.now(timezone.utc).isoformat()),
            end_time=mission_data.get("end_time", datetime.now(timezone.utc).isoformat()),
            duration_seconds=mission_data.get("duration_seconds", 0),
            targets_scanned=mission_data.get("targets_scanned", 0),
            modules_executed=mission_data.get("modules_executed", []),
            total_findings=len(findings),
            findings_by_severity=self._count_by_severity(findings),
            risk_score=self._calculate_risk_score(findings),
            scope_hash=mission_data.get("scope_hash", "")
        )
        
        compliance_status = self._assess_compliance(findings)
        
        executive_summary = self._generate_executive_summary(mission_summary, findings)
        
        risk_assessment = self._generate_risk_assessment(findings)
        
        recommendations = self._generate_recommendations(findings)
        
        report = Report(
            report_id=f"RPT-{uuid.uuid4().hex[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            report_version="2.0.0",
            mission_summary=mission_summary,
            findings=findings,
            compliance_status=compliance_status,
            executive_summary=executive_summary,
            risk_assessment=risk_assessment,
            recommendations=recommendations
        )
        
        report.checksum = self._compute_checksum(report)
        
        return report
    
    def _process_findings(self, findings_data: List[Dict[str, Any]]) -> List[Finding]:
        """Process and enrich findings."""
        findings = []
        for idx, data in enumerate(findings_data):
            finding = Finding(
                finding_id=data.get("finding_id", f"FIND-{idx+1:04d}"),
                title=data.get("title", "Unknown Finding"),
                severity=data.get("severity", "medium"),
                category=data.get("category", "general"),
                description=data.get("description", ""),
                target=data.get("target", ""),
                evidence=data.get("evidence", ""),
                remediation=data.get("remediation", ""),
                cvss_score=data.get("cvss_score"),
                cve_id=data.get("cve_id"),
                cwe_id=data.get("cwe_id"),
                references=data.get("references", []),
                validated=data.get("validated", False)
            )
            
            finding.compliance_mappings = ComplianceMapper.map_finding(
                finding, self.compliance_frameworks
            )
            
            findings.append(finding)
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity.lower(), 5))
        
        return findings
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for finding in findings:
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate overall risk score (0-100)."""
        if not findings:
            return 0.0
        
        severity_weights = {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 3,
            "informational": 1
        }
        
        total_weight = sum(
            severity_weights.get(f.severity.lower(), 5) for f in findings
        )
        
        max_score = len(findings) * severity_weights["critical"]
        risk_score = min(100.0, (total_weight / max(max_score, 1)) * 100)
        
        return round(risk_score, 2)
    
    def _assess_compliance(self, findings: List[Finding]) -> List[ComplianceStatus]:
        """Assess compliance against each framework."""
        compliance_results = []
        
        for framework in self.compliance_frameworks:
            all_controls = set()
            for category in ComplianceMapper.CONTROL_MAPPINGS.get(framework, {}).values():
                all_controls.update(category)
            
            failed_controls = set()
            for finding in findings:
                if finding.severity.lower() in ["critical", "high", "medium"]:
                    controls = ComplianceMapper.get_controls(framework, finding.category)
                    failed_controls.update(controls)
            
            passed = len(all_controls) - len(failed_controls)
            total = len(all_controls)
            
            compliance_results.append(ComplianceStatus(
                framework=framework.value.upper(),
                controls_tested=total,
                controls_passed=passed,
                controls_failed=len(failed_controls),
                compliance_percentage=round((passed / max(total, 1)) * 100, 2),
                failed_controls=[
                    {"control_id": ctrl, "status": "FAILED"}
                    for ctrl in sorted(failed_controls)
                ]
            ))
        
        return compliance_results
    
    def _generate_executive_summary(
        self,
        mission: MissionSummary,
        findings: List[Finding]
    ) -> str:
        """Generate executive summary text."""
        critical_high = mission.findings_by_severity.get("critical", 0) + \
                       mission.findings_by_severity.get("high", 0)
        
        risk_level = "LOW"
        if mission.risk_score >= 70:
            risk_level = "CRITICAL"
        elif mission.risk_score >= 50:
            risk_level = "HIGH"
        elif mission.risk_score >= 25:
            risk_level = "MEDIUM"
        
        summary = f"""EXECUTIVE SUMMARY

Assessment Overview:
This security assessment was conducted for {mission.client_name} from {mission.start_time[:10]} to {mission.end_time[:10]}. The assessment covered {mission.targets_scanned} target(s) using {len(mission.modules_executed)} security module(s).

Key Findings:
A total of {mission.total_findings} security findings were identified during this assessment. Of these, {critical_high} are classified as Critical or High severity and require immediate attention.

Risk Assessment:
The overall security posture is rated as {risk_level} with a risk score of {mission.risk_score}/100. """
        
        if risk_level in ["CRITICAL", "HIGH"]:
            summary += "Immediate remediation is strongly recommended to address the identified vulnerabilities."
        elif risk_level == "MEDIUM":
            summary += "Remediation should be prioritized based on business impact and exposure."
        else:
            summary += "The organization demonstrates a solid security foundation with room for improvement."
        
        return summary
    
    def _generate_risk_assessment(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate detailed risk assessment."""
        categories = {}
        for finding in findings:
            cat = finding.category
            if cat not in categories:
                categories[cat] = {"count": 0, "severities": []}
            categories[cat]["count"] += 1
            categories[cat]["severities"].append(finding.severity)
        
        category_risks = []
        for cat, data in categories.items():
            severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
            avg_severity = sum(severity_weights.get(s.lower(), 1) for s in data["severities"]) / len(data["severities"])
            category_risks.append({
                "category": cat,
                "finding_count": data["count"],
                "average_severity_score": round(avg_severity, 2),
                "risk_level": "HIGH" if avg_severity >= 3 else "MEDIUM" if avg_severity >= 2 else "LOW"
            })
        
        return {
            "risk_categories": sorted(category_risks, key=lambda x: -x["average_severity_score"]),
            "highest_risk_category": max(category_risks, key=lambda x: x["average_severity_score"])["category"] if category_risks else None,
            "attack_surface_score": min(100, len(findings) * 5),
            "vulnerability_density": round(len(findings) / max(1, len(categories)), 2)
        }
    
    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        critical = [f for f in findings if f.severity.lower() == "critical"]
        if critical:
            recommendations.append(
                f"IMMEDIATE: Address {len(critical)} critical vulnerabilities within 24-48 hours. "
                f"These include: {', '.join(f.title for f in critical[:3])}"
            )
        
        high = [f for f in findings if f.severity.lower() == "high"]
        if high:
            recommendations.append(
                f"HIGH PRIORITY: Remediate {len(high)} high-severity findings within 1-2 weeks."
            )
        
        categories = set(f.category for f in findings)
        if "ssl_tls" in str(categories).lower() or "encryption" in str(categories).lower():
            recommendations.append(
                "Implement TLS 1.3 across all services and disable legacy protocols."
            )
        
        if "xss" in str(categories).lower() or "injection" in str(categories).lower():
            recommendations.append(
                "Deploy Web Application Firewall (WAF) and implement input validation."
            )
        
        if "security_headers" in str(categories).lower():
            recommendations.append(
                "Configure security headers (CSP, HSTS, X-Frame-Options) on all web services."
            )
        
        recommendations.append(
            "Conduct follow-up assessment in 30-60 days to verify remediation effectiveness."
        )
        
        return recommendations
    
    def _compute_checksum(self, report: Report) -> str:
        """Compute SHA-256 checksum for report integrity."""
        report_dict = asdict(report)
        report_dict.pop("checksum", None)
        content = json.dumps(report_dict, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _render_report(self, report: Report, fmt: ReportFormat) -> Path:
        """Render report in specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{report.mission_summary.mission_id}_{timestamp}"
        
        if fmt == ReportFormat.JSON:
            return self._render_json(report, base_name)
        elif fmt == ReportFormat.HTML:
            return self._render_html(report, base_name)
        elif fmt == ReportFormat.MARKDOWN:
            return self._render_markdown(report, base_name)
        elif fmt == ReportFormat.TEXT:
            return self._render_text(report, base_name)
        elif fmt == ReportFormat.EXECUTIVE:
            return self._render_executive(report, base_name)
        else:
            raise ValueError(f"Unsupported format: {fmt}")
    
    def _render_json(self, report: Report, base_name: str) -> Path:
        """Render JSON report."""
        filepath = self.output_dir / f"{base_name}.json"
        with open(filepath, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        return filepath
    
    def _render_html(self, report: Report, base_name: str) -> Path:
        """Render HTML report."""
        filepath = self.output_dir / f"{base_name}.html"
        
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "informational": "#17a2b8"
        }
        
        findings_html = ""
        for finding in report.findings:
            color = severity_colors.get(finding.severity.lower(), "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 15px; margin: 10px 0; background: #f8f9fa;">
                <h4>{html.escape(finding.title)}</h4>
                <span class="badge" style="background: {color}; color: white; padding: 3px 8px; border-radius: 3px;">
                    {finding.severity.upper()}
                </span>
                <p><strong>Target:</strong> {html.escape(finding.target)}</p>
                <p><strong>Description:</strong> {html.escape(finding.description)}</p>
                <p><strong>Remediation:</strong> {html.escape(finding.remediation)}</p>
                {f'<p><strong>CVSS:</strong> {finding.cvss_score}</p>' if finding.cvss_score else ''}
            </div>
            """
        
        compliance_html = ""
        for status in report.compliance_status:
            bar_color = "#28a745" if status.compliance_percentage >= 80 else "#ffc107" if status.compliance_percentage >= 60 else "#dc3545"
            compliance_html += f"""
            <div class="compliance-item" style="margin: 15px 0;">
                <h4>{status.framework}</h4>
                <div style="background: #e9ecef; border-radius: 5px; height: 25px;">
                    <div style="background: {bar_color}; width: {status.compliance_percentage}%; height: 100%; border-radius: 5px; text-align: center; color: white; line-height: 25px;">
                        {status.compliance_percentage}%
                    </div>
                </div>
                <p>Controls: {status.controls_passed}/{status.controls_tested} passed</p>
            </div>
            """
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {html.escape(report.mission_summary.client_name)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #fff; color: #333; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 2em; }}
        .header p {{ margin: 10px 0 0; opacity: 0.9; }}
        .section {{ margin: 30px 0; padding: 20px; border: 1px solid #e9ecef; border-radius: 8px; }}
        .section h2 {{ color: #1a1a2e; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .metric-label {{ color: #6c757d; margin-top: 5px; }}
        .risk-score {{ font-size: 3em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Assessment Report</h1>
        <p>Report ID: {report.report_id} | Generated: {report.generated_at[:10]}</p>
        <p>Client: {html.escape(report.mission_summary.client_name)} | Mission: {report.mission_summary.mission_id}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <pre style="white-space: pre-wrap; font-family: inherit;">{html.escape(report.executive_summary)}</pre>
    </div>
    
    <div class="section">
        <h2>📈 Key Metrics</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{report.mission_summary.total_findings}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #dc3545;">{report.mission_summary.findings_by_severity.get('critical', 0)}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #fd7e14;">{report.mission_summary.findings_by_severity.get('high', 0)}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric">
                <div class="metric-value">{report.mission_summary.risk_score}</div>
                <div class="metric-label">Risk Score /100</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>✅ Compliance Status</h2>
        {compliance_html}
    </div>
    
    <div class="section">
        <h2>🔍 Detailed Findings</h2>
        {findings_html}
    </div>
    
    <div class="section">
        <h2>📋 Recommendations</h2>
        <ol>
            {''.join(f'<li style="margin: 10px 0;">{html.escape(rec)}</li>' for rec in report.recommendations)}
        </ol>
    </div>
    
    <div class="footer">
        <p>ZumrutAutomation Security Assessment Platform</p>
        <p>Report Checksum: {report.checksum[:16]}...</p>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        return filepath
    
    def _render_markdown(self, report: Report, base_name: str) -> Path:
        """Render Markdown report."""
        filepath = self.output_dir / f"{base_name}.md"
        
        md_content = f"""# Security Assessment Report

**Report ID:** {report.report_id}  
**Generated:** {report.generated_at}  
**Client:** {report.mission_summary.client_name}  
**Mission:** {report.mission_summary.mission_id}

---

## Executive Summary

{report.executive_summary}

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Findings | {report.mission_summary.total_findings} |
| Critical | {report.mission_summary.findings_by_severity.get('critical', 0)} |
| High | {report.mission_summary.findings_by_severity.get('high', 0)} |
| Medium | {report.mission_summary.findings_by_severity.get('medium', 0)} |
| Low | {report.mission_summary.findings_by_severity.get('low', 0)} |
| Risk Score | {report.mission_summary.risk_score}/100 |
| Targets Scanned | {report.mission_summary.targets_scanned} |

---

## Compliance Status

"""
        for status in report.compliance_status:
            md_content += f"""### {status.framework}
- **Compliance:** {status.compliance_percentage}%
- **Controls Passed:** {status.controls_passed}/{status.controls_tested}
- **Controls Failed:** {status.controls_failed}

"""
        
        md_content += """---

## Detailed Findings

"""
        for finding in report.findings:
            md_content += f"""### [{finding.severity.upper()}] {finding.title}

- **ID:** {finding.finding_id}
- **Category:** {finding.category}
- **Target:** {finding.target}
- **CVSS:** {finding.cvss_score or 'N/A'}

**Description:**  
{finding.description}

**Evidence:**  
{finding.evidence}

**Remediation:**  
{finding.remediation}

---

"""
        
        md_content += """## Recommendations

"""
        for i, rec in enumerate(report.recommendations, 1):
            md_content += f"{i}. {rec}\n"
        
        md_content += f"""
---

*Report Checksum: `{report.checksum}`*  
*Generated by ZumrutAutomation*
"""
        
        with open(filepath, 'w') as f:
            f.write(md_content)
        return filepath
    
    def _render_text(self, report: Report, base_name: str) -> Path:
        """Render plain text report."""
        filepath = self.output_dir / f"{base_name}.txt"
        
        separator = "=" * 80
        
        text_content = f"""{separator}
                    SECURITY ASSESSMENT REPORT
{separator}

Report ID:    {report.report_id}
Generated:    {report.generated_at}
Client:       {report.mission_summary.client_name}
Mission ID:   {report.mission_summary.mission_id}

{separator}
                       EXECUTIVE SUMMARY
{separator}

{report.executive_summary}

{separator}
                         KEY METRICS
{separator}

Total Findings:    {report.mission_summary.total_findings}
  - Critical:      {report.mission_summary.findings_by_severity.get('critical', 0)}
  - High:          {report.mission_summary.findings_by_severity.get('high', 0)}
  - Medium:        {report.mission_summary.findings_by_severity.get('medium', 0)}
  - Low:           {report.mission_summary.findings_by_severity.get('low', 0)}
  - Informational: {report.mission_summary.findings_by_severity.get('informational', 0)}

Risk Score:        {report.mission_summary.risk_score}/100
Targets Scanned:   {report.mission_summary.targets_scanned}

{separator}
                      COMPLIANCE STATUS
{separator}

"""
        for status in report.compliance_status:
            text_content += f"""
{status.framework}:
  Compliance:      {status.compliance_percentage}%
  Controls Passed: {status.controls_passed}/{status.controls_tested}
  Controls Failed: {status.controls_failed}
"""
        
        text_content += f"""
{separator}
                      DETAILED FINDINGS
{separator}
"""
        for finding in report.findings:
            text_content += f"""
[{finding.severity.upper()}] {finding.title}
{'-' * 60}
ID:          {finding.finding_id}
Category:    {finding.category}
Target:      {finding.target}
CVSS:        {finding.cvss_score or 'N/A'}

Description:
{finding.description}

Evidence:
{finding.evidence}

Remediation:
{finding.remediation}

"""
        
        text_content += f"""
{separator}
                      RECOMMENDATIONS
{separator}

"""
        for i, rec in enumerate(report.recommendations, 1):
            text_content += f"{i}. {rec}\n\n"
        
        text_content += f"""
{separator}
Report Checksum: {report.checksum}
Generated by ZumrutAutomation Security Assessment Platform
{separator}
"""
        
        with open(filepath, 'w') as f:
            f.write(text_content)
        return filepath
    
    def _render_executive(self, report: Report, base_name: str) -> Path:
        """Render executive-only summary (1-page format)."""
        filepath = self.output_dir / f"{base_name}_executive.pdf.txt"
        
        risk_level = "LOW"
        if report.mission_summary.risk_score >= 70:
            risk_level = "CRITICAL"
        elif report.mission_summary.risk_score >= 50:
            risk_level = "HIGH"
        elif report.mission_summary.risk_score >= 25:
            risk_level = "MEDIUM"
        
        content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     EXECUTIVE SECURITY BRIEFING                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Client: {report.mission_summary.client_name:<62} ║
║  Date:   {report.generated_at[:10]:<62} ║
║  Risk:   {risk_level:<62} ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│ RISK SCORE: {report.mission_summary.risk_score}/100                                                      │
│ {'█' * int(report.mission_summary.risk_score // 2):<50} │
└─────────────────────────────────────────────────────────────────────────────┘

FINDINGS SUMMARY:
  ● Critical: {report.mission_summary.findings_by_severity.get('critical', 0):>3}    ● High: {report.mission_summary.findings_by_severity.get('high', 0):>3}    ● Medium: {report.mission_summary.findings_by_severity.get('medium', 0):>3}    ● Low: {report.mission_summary.findings_by_severity.get('low', 0):>3}

TOP 3 PRIORITIES:
"""
        for i, rec in enumerate(report.recommendations[:3], 1):
            content += f"  {i}. {rec[:70]}...\n" if len(rec) > 70 else f"  {i}. {rec}\n"
        
        content += f"""
COMPLIANCE SNAPSHOT:
"""
        for status in report.compliance_status[:4]:
            bar = '█' * int(status.compliance_percentage // 10) + '░' * (10 - int(status.compliance_percentage // 10))
            content += f"  {status.framework:<8} [{bar}] {status.compliance_percentage}%\n"
        
        content += """
─────────────────────────────────────────────────────────────────────────────
                         CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY
"""
        
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath


def main():
    """Test report generation."""
    engine = ReportEngine()
    
    mission_data = {
        "mission_id": "MISSION-TEST-001",
        "client_name": "ACME Corporation",
        "start_time": "2026-01-11T10:00:00Z",
        "end_time": "2026-01-11T14:30:00Z",
        "duration_seconds": 16200,
        "targets_scanned": 5,
        "modules_executed": ["web_scanner", "network_scanner", "ssl_analyzer"],
        "scope_hash": "abc123def456"
    }
    
    findings_data = [
        {
            "title": "TLS 1.0 Enabled",
            "severity": "high",
            "category": "ssl_tls",
            "description": "Server accepts TLS 1.0 connections which are vulnerable to POODLE and BEAST attacks.",
            "target": "https://example.com",
            "evidence": "TLS 1.0 handshake successful",
            "remediation": "Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and 1.3.",
            "cvss_score": 7.5
        },
        {
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "category": "security_headers",
            "description": "The Content-Security-Policy header is not configured.",
            "target": "https://example.com",
            "evidence": "CSP header not present in response",
            "remediation": "Implement a strict Content-Security-Policy header.",
            "cvss_score": 5.0
        },
        {
            "title": "Reflected XSS in Search Parameter",
            "severity": "critical",
            "category": "xss",
            "description": "User input in the 'q' parameter is reflected without sanitization.",
            "target": "https://example.com/search?q=test",
            "evidence": "<script>alert(1)</script> payload executed",
            "remediation": "Implement output encoding and input validation.",
            "cvss_score": 9.1,
            "cwe_id": "CWE-79"
        }
    ]
    
    reports = engine.generate_report(
        mission_data,
        findings_data,
        formats=[ReportFormat.JSON, ReportFormat.HTML, ReportFormat.MARKDOWN, 
                 ReportFormat.TEXT, ReportFormat.EXECUTIVE]
    )
    
    print("\n[+] Generated Reports:")
    for fmt, path in reports.items():
        print(f"    - {fmt}: {path}")


if __name__ == "__main__":
    main()
