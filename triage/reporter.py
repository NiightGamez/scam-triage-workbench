"""Report generation for Scam Triage Workbench (JSON, Markdown, CLI Terminal)."""

from __future__ import annotations

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from triage.models import RiskSeverity, RiskTier, TriageReport


def to_json(report: TriageReport, indent: int = 2) -> str:
    """Serialize the triage report to a clean JSON string."""
    return report.model_dump_json(indent=indent)


def to_markdown(report: TriageReport) -> str:
    """Generate a clean, professional Markdown triage report for SOC analysts."""
    t = report.target
    ra = report.risk_assessment
    dns = report.dns
    rdap = report.rdap
    ct = report.ct_logs

    # Tier color/badge
    tier_badges = {
        RiskTier.LOW: "🟢 **LOW RISK**",
        RiskTier.MEDIUM: "🟡 **MEDIUM RISK**",
        RiskTier.HIGH: "🟠 **HIGH RISK**",
        RiskTier.CRITICAL: "🔴 **CRITICAL RISK**",
    }
    tier_badge = tier_badges.get(ra.tier, f"**{ra.tier.value}**")

    lines = [
        f"# Scam & Phishing Infrastructure Triage Report",
        f"",
        f"**Target (Defanged):** `{t.defanged_target}`  ",
        f"**Target Type:** `{t.target_type.value}` | **Host:** `{t.defanged_host}` | **Registrable Domain:** `{t.domain}`  ",
        f"**Analysis Timestamp:** `{report.timestamp}`  ",
        f"**Composite Risk Score:** `{ra.score}/100` — {tier_badge}  ",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary & Risk Flags",
        f"",
    ]

    if not ra.flags:
        lines.append("No automated risk flags were triggered during passive triage.")
        lines.append("")
    else:
        lines.append("| Flag ID | Severity | Points | Name & Description | Evidence |")
        lines.append("| :--- | :---: | :---: | :--- | :--- |")
        for flag in ra.flags:
            ev = f"`{flag.evidence}`" if flag.evidence else "N/A"
            sev_emoji = {
                RiskSeverity.CRITICAL: "🔴",
                RiskSeverity.HIGH: "🟠",
                RiskSeverity.MEDIUM: "🟡",
                RiskSeverity.LOW: "🔵",
                RiskSeverity.INFO: "⚪",
            }.get(flag.severity, "")
            lines.append(
                f"| `{flag.id}` | {sev_emoji} {flag.severity.value} | +{flag.score_impact} | "
                f"**{flag.name}**<br>{flag.description} | {ev} |"
            )
        lines.append("")

    # 2. DNS Infrastructure
    lines.extend([
        f"## 2. Passive DNS Infrastructure",
        f"",
    ])

    if dns.error:
        lines.append(f"> [!WARNING]  \n> DNS Resolution Notice: {dns.error}\n")

    # A / AAAA Records Table
    if dns.a_records or dns.aaaa_records:
        lines.append("### IP Address Resolution")
        lines.append("| Type | IP Address (Defanged) | TTL |")
        lines.append("| :---: | :--- | :---: |")
        for rec in dns.a_records:
            lines.append(f"| A (IPv4) | `{rec.value.replace('.', '[.]')}` | {rec.ttl or 'N/A'}s |")
        for rec in dns.aaaa_records:
            lines.append(f"| AAAA (IPv6) | `{rec.value.replace(':', '[:]')}` | {rec.ttl or 'N/A'}s |")
        lines.append("")
    else:
        lines.append("No active A or AAAA records resolved.")
        lines.append("")

    # Mail & Nameservers
    lines.append("### Mail & Nameserver Records")
    if dns.mx_records:
        lines.append("- **MX Records:**")
        for mx in dns.mx_records:
            lines.append(f"  - Preference {mx.preference}: `{mx.host}` (TTL: {mx.ttl or 'N/A'}s)")
    else:
        lines.append("- **MX Records:** None detected")

    if dns.ns_records:
        lines.append(f"- **Nameservers:** {', '.join(f'`{ns}`' for ns in dns.ns_records)}")
    else:
        lines.append("- **Nameservers:** None detected")
    lines.append("")

    # Email Security Protocols
    lines.append("### Email Authentication (SPF / DMARC)")
    lines.append(f"- **SPF Record:** {f'`{dns.spf_record}`' if dns.spf_record else '*None published*'}")
    lines.append(f"- **DMARC Record:** {f'`{dns.dmarc_record}`' if dns.dmarc_record else '*None published*'}")
    lines.append("")

    # 3. Domain Registration (RDAP)
    lines.extend([
        f"## 3. Domain Registration & RDAP",
        f"",
    ])
    if rdap and rdap.queried and not rdap.error:
        age_str = f"{rdap.age_days} days" if rdap.age_days is not None else "Unknown"
        exp_str = f"{rdap.days_until_expiration} days" if rdap.days_until_expiration is not None else "Unknown"
        lines.append(f"| Attribute | Value |")
        lines.append(f"| :--- | :--- |")
        lines.append(f"| **Registrar** | {rdap.registrar or 'Unknown'} |")
        lines.append(f"| **Registration Date** | {rdap.creation_date or 'N/A'} |")
        lines.append(f"| **Domain Age** | **{age_str}** |")
        lines.append(f"| **Expiration Date** | {rdap.expiration_date or 'N/A'} ({exp_str} remaining) |")
        lines.append(f"| **Last Updated** | {rdap.updated_date or 'N/A'} |")
        if rdap.status:
            lines.append(f"| **Domain Statuses** | {', '.join(f'`{s}`' for s in rdap.status)} |")
        lines.append("")
    elif rdap and rdap.error:
        lines.append(f"> [!NOTE]  \n> RDAP query status: {rdap.error}\n")
    else:
        lines.append("RDAP query was skipped or unavailable.\n")

    # 4. Public ASN & Hosting Infrastructure
    lines.extend([
        f"## 4. Hosting Infrastructure & ASN",
        f"",
    ])
    if report.ip_enrichments:
        lines.append("| IP Address | ASN | Organization / AS Name | BGP Prefix | Country |")
        lines.append("| :--- | :--- | :--- | :--- | :---: |")
        for ip_e in report.ip_enrichments:
            asn_val = f"`{ip_e.asn}`" if ip_e.asn else "N/A"
            as_name_val = ip_e.as_name or "Unknown"
            cidr_val = f"`{ip_e.bgp_prefix}`" if ip_e.bgp_prefix else "N/A"
            cc_val = ip_e.country_code or "N/A"
            lines.append(f"| `{ip_e.defanged_ip}` | {asn_val} | {as_name_val} | {cidr_val} | {cc_val} |")
        lines.append("")
    else:
        lines.append("No IP addresses available for ASN lookup.\n")

    # 5. Certificate Transparency (crt.sh)
    lines.extend([
        f"## 5. Certificate Transparency Subdomain Discovery (crt.sh)",
        f"",
    ])
    if ct and ct.queried and not ct.error:
        lines.append(f"- **Discovered Subdomain Count:** `{ct.subdomain_count}`")
        if ct.subdomains:
            lines.append("")
            lines.append("<details><summary>Click to view all discovered subdomains</summary>")
            lines.append("")
            for sub in ct.subdomains:
                lines.append(f"- `{sub}`")
            lines.append("")
            lines.append("</details>")
            lines.append("")
    elif ct and ct.error:
        lines.append(f"> [!NOTE]  \n> crt.sh status: {ct.error}\n")
    else:
        lines.append("No CT subdomain query performed.\n")

    # Methodology & Security Statement
    lines.extend([
        f"---",
        f"",
        f"> [!NOTE]",
        f"> **Passive OSINT & SSRF Guardrail Statement:**",
        f"> All data in this report was collected 100% passively through trusted public APIs (public DNS, rdap.org, crt.sh, Team Cymru ASN).",
        f"> Zero packets or HTTP requests were transmitted to the investigated target or any private IP space.",
    ])

    return "\n".join(lines)


def print_cli_summary(report: TriageReport) -> None:
    """Print an eye-catching, formatted summary to terminal using Rich."""
    console = Console()
    t = report.target
    ra = report.risk_assessment

    tier_colors = {
        RiskTier.LOW: "bold green",
        RiskTier.MEDIUM: "bold yellow",
        RiskTier.HIGH: "bold dark_orange",
        RiskTier.CRITICAL: "bold red on white",
    }
    tier_style = tier_colors.get(ra.tier, "bold cyan")

    # Header Panel
    header_content = (
        f"[bold]Target (Defanged):[/bold] [cyan]{t.defanged_target}[/cyan]\n"
        f"[bold]Type:[/bold] {t.target_type.value} | [bold]Host:[/bold] {t.defanged_host} | [bold]Domain:[/bold] {t.domain}\n"
        f"[bold]Risk Score:[/bold] [{tier_style}]{ra.score}/100 — {ra.tier.value} RISK[/{tier_style}]"
    )
    console.print(Panel(header_content, title="🛡️ Scam & Phishing Infrastructure Triage", border_style="bright_blue"))

    # Risk Flags Table
    if ra.flags:
        flags_table = Table(title="🚨 Automated Heuristic Risk Flags", expand=True)
        flags_table.add_column("Flag ID", style="cyan", no_wrap=True)
        flags_table.add_column("Severity", justify="center")
        flags_table.add_column("Impact", justify="right", style="yellow")
        flags_table.add_column("Name & Evidence", style="white")

        sev_styles = {
            RiskSeverity.CRITICAL: "[bold red]CRITICAL[/bold red]",
            RiskSeverity.HIGH: "[bold orange3]HIGH[/bold orange3]",
            RiskSeverity.MEDIUM: "[yellow]MEDIUM[/yellow]",
            RiskSeverity.LOW: "[blue]LOW[/blue]",
            RiskSeverity.INFO: "[white]INFO[/white]",
        }

        for f in ra.flags:
            sev_badge = sev_styles.get(f.severity, f.severity.value)
            ev = f"\n[dim]Evidence: {f.evidence}[/dim]" if f.evidence else ""
            flags_table.add_row(f.id, sev_badge, f"+{f.score_impact}", f"[bold]{f.name}[/bold]{ev}")

        console.print(flags_table)
    else:
        console.print("[green]✓ No heuristic risk flags triggered.[/green]")

    # Infrastructure Table
    infra_table = Table(title="🌐 Infrastructure Summary", expand=True)
    infra_table.add_column("Category", style="cyan", no_wrap=True)
    infra_table.add_column("Details", style="white")

    # Resolved IPs
    ip_list = [r.value.replace(".", "[.]") for r in report.dns.a_records]
    if ip_list:
        infra_table.add_row("IPv4 (A)", ", ".join(ip_list))
    else:
        infra_table.add_row("IPv4 (A)", "[dim]None resolved[/dim]")

    # ASN Info
    if report.ip_enrichments:
        asn_strs = []
        seen_asn = set()
        for e in report.ip_enrichments:
            if e.asn and e.asn not in seen_asn:
                seen_asn.add(e.asn)
                asn_strs.append(f"{e.asn} ({e.as_name or 'Unknown'}, {e.country_code or '??'})")
        if asn_strs:
            infra_table.add_row("ASN / Org", "; ".join(asn_strs))

    # Email auth
    spf_str = report.dns.spf_record or "[red]Missing[/red]"
    dmarc_str = report.dns.dmarc_record or "[red]Missing[/red]"
    infra_table.add_row("Email Auth", f"SPF: {spf_str}\nDMARC: {dmarc_str}")

    # RDAP
    if report.rdap and report.rdap.queried and not report.rdap.error:
        age = f"{report.rdap.age_days} days" if report.rdap.age_days is not None else "Unknown"
        infra_table.add_row("Domain Age", f"{age} (Registrar: {report.rdap.registrar or 'Unknown'})")

    # CT Subdomains
    if report.ct_logs and report.ct_logs.queried:
        infra_table.add_row("CT Subdomains", f"{report.ct_logs.subdomain_count} discovered via crt.sh")

    console.print(infra_table)
