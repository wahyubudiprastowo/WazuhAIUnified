"""Deterministic SOC detection labels derived from already-decoded evidence.

This module deliberately classifies only the evidence that Wazuh has indexed.
It does not turn keyword matches into a claim that an exploit succeeded.
"""
from __future__ import annotations

import re
from typing import Any


FAMILIES = (
    ("mitm_suspected", ("man in the middle", "mitm", "arp spoof", "arp poisoning", "ssl strip", "tls downgrade"), ("T1557",)),
    ("sniffing", ("packet sniff", "network sniff", "promiscuous mode", "pcap capture"), ("T1040",)),
    ("beaconing", ("beaconing", "periodic beacon", "c2 beacon", "command and control beacon"), ("T1071",)),
    ("dos", ("ddos", "denial of service", "dos attack", "syn flood", "udp flood", "icmp flood"), ("T1498",)),
    ("web_attack.sqli", ("sql injection", "sqli", "union select", "sql syntax"), ("T1190",)),
    ("web_attack.xss", ("cross site scripting", "cross-site scripting", "xss", "script injection"), ("T1190",)),
    ("exploit_attempt", ("exploit", "remote code execution", "rce", "buffer overflow", "command injection", "attack dropped", "attack detected"), ("T1190",)),
    ("bruteforce", ("brute force", "password spray", "failed password", "authentication failed", "login failed", "logon failure"), ("T1110",)),
    ("scan", ("nmap", "port scan", "network scan", "service scan", "fingerprint attempt", "reconnaissance"), ("T1595",)),
    ("malware", ("malware", "ransomware", "trojan", "virus", "backdoor", "rootkit", "cobalt strike"), ()),
    ("phishing", ("phishing", "malicious email", "user submission", "mail threat", "timaildata"), ("T1566",)),
)

_NETWORK_FIELDS = ("source_ip", "destination_ip", "destination_port", "action")


def _nested(source: dict[str, Any], path: str) -> Any:
    value: Any = source
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _first(source: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested(source, path)
        if value not in (None, "", []):
            return value
    return None


def event_fields(event: dict[str, Any] | None) -> dict[str, Any]:
    """Return a bounded, non-sensitive projection used for confidence only."""
    event = event or {}
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    return {
        "rule_id": rule.get("id"),
        "source_ip": _first(event, "data.srcip", "data.src_ip", "data.source.ip", "data.office365.ClientIP"),
        "destination_ip": _first(event, "data.dstip", "data.dst_ip", "data.destination.ip"),
        "destination_port": _first(event, "data.dstport", "data.dst_port", "data.destination.port"),
        "action": _first(event, "data.action", "data.event.action", "data.status"),
        "forti_type": _first(event, "data.type"),
        "forti_subtype": _first(event, "data.subtype"),
        "identity": _first(event, "data.office365.UserId", "data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName", "data.user"),
        "url": _first(event, "data.url", "data.http.url", "data.full_url", "data.request"),
        "application": _first(event, "data.app", "data.application", "data.service", "data.appcat"),
        "firewall_policy": _first(event, "data.policyid", "data.policy_id", "data.policyname", "data.rule_name"),
        "direction": _first(event, "data.direction", "data.flow_direction"),
        "protocol": _first(event, "data.proto", "data.protocol", "data.network.protocol"),
        "host": _first(event, "agent.name", "data.hostname", "data.host"),
        "process": _first(event, "data.win.eventdata.image", "data.process.name", "data.process"),
        "parent_process": _first(event, "data.win.eventdata.parentImage", "data.parent_process"),
        "hash": _first(event, "data.hash", "data.win.eventdata.hashes", "data.file_hash"),
        "workload": _first(event, "data.office365.Workload"),
        "operation": _first(event, "data.office365.Operation"),
        "object": _first(event, "data.office365.ObjectId", "data.object"),
        "session": _first(event, "data.office365.SessionId", "data.session", "data.logon_id"),
        "exe": _first(event, "data.audit.exe", "data.exe"),
        "command": _first(event, "data.audit.command", "data.command", "data.cmd"),
        "uid": _first(event, "data.audit.uid", "data.uid"),
        "container": _first(event, "data.docker.container.id", "data.docker.container.name",
                            "data.container.id", "data.container.name", "data.container_name"),
        "image": _first(event, "data.docker.image", "data.container.image", "data.image"),
    }


def _haystack(event: dict[str, Any]) -> str:
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    decoder = event.get("decoder") if isinstance(event.get("decoder"), dict) else {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    values = [rule.get("description"), decoder.get("name"), event.get("category"), event.get("title"), *groups]
    return " ".join(str(value) for value in values if value).lower()


def _contains_signal(haystack: str, term: str) -> bool:
    # Short attack acronyms (for example RCE) must be tokens: substring
    # matching makes "force" look like an RCE signal.
    if term.isalnum() and len(term) <= 4:
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", haystack, re.I) is not None
    return term in haystack


def classify(event: dict[str, Any] | None, provider_only: bool = False) -> dict[str, Any]:
    """Classify a decoded record without asserting compromise or attribution."""
    event = event or {}
    haystack = _haystack(event)
    family, mitre = "other", ()
    for candidate, terms, techniques in FAMILIES:
        if any(_contains_signal(haystack, term) for term in terms):
            family, mitre = candidate, techniques
            break
    fields = event_fields(event)
    # FortiGate's built-in Wazuh decoder exposes security subtypes even when a
    # vendor rule description is terse. Do not turn ordinary forward/app-control
    # traffic into an attack: only IPS evidence and explicit malware telemetry
    # receive a security family.
    if family == "other" and telemetry_source(event) == "fortigate":
        subtype = str(fields.get("forti_subtype") or "").lower()
        action = str(fields.get("action") or "").lower()
        if subtype in {"virus", "antivirus"}:
            family = "malware"
        elif subtype == "ips" and action not in {"", "pass", "accept", "allow", "monitor"}:
            family = "exploit_attempt"
    missing: list[str] = []
    if family in {"bruteforce", "scan", "dos", "mitm_suspected", "sniffing", "beaconing", "exploit_attempt"}:
        missing = [field for field in _NETWORK_FIELDS if not fields.get(field)]
    elif family.startswith("web_attack"):
        missing = [field for field in ("source_ip", "destination_ip", "url", "action") if not fields.get(field)]
    elif family == "phishing":
        missing = [field for field in ("identity", "source_ip") if not fields.get(field)]
    elif family == "malware":
        # Process/hash fields are intentionally not inferred from an alert title.
        missing = ["hash_or_process_evidence"]

    if provider_only:
        confidence = "provider_only"
    elif not fields.get("rule_id"):
        confidence = "telemetry_missing"
    elif not missing:
        confidence = "evidence_complete"
    else:
        confidence = "rule_matched"
    return {
        "family": family,
        "mitre": list(mitre),
        "confidence": confidence,
        "missing_evidence": missing,
        "fields": fields,
        "assertion": "attempt_or_signal" if family != "other" else "unclassified_signal",
    }


def consensus_confidence(event: dict[str, Any] | None, provider_matches: int = 0,
                         provider_only: bool = False) -> dict[str, Any]:
    """Add a bounded provider-consensus state without claiming compromise.

    ``confirmed_by_multi_source`` means decoded local evidence and at least one
    stored external provider match corroborate the same finding. It does not
    mean that an exploit or intrusion has been confirmed.
    """
    result = classify(event, provider_only=provider_only)
    if not provider_only and int(provider_matches or 0) > 0 and result["confidence"] == "evidence_complete":
        result["confidence"] = "confirmed_by_multi_source"
    return result


def telemetry_source(event: dict[str, Any] | None) -> str:
    event = event or {}
    decoder = str(_nested(event, "decoder.name") or "").lower()
    provider = str(_nested(event, "data.win.system.providerName") or
                   _nested(event, "data.win.system.provider_name") or "").lower()
    channel = str(_nested(event, "data.win.system.channel") or "").lower()
    if _nested(event, "data.office365.Workload"):
        return "m365_audit"
    if "fortiweb" in decoder:
        return "fortiweb"
    if "fortigate" in decoder:
        return "fortigate"
    if "sangfor" in decoder:
        return "sangfor_firewall"
    if any(term in decoder for term in ("modsecurity", "waf", "nginx", "apache", "iis")):
        return "waf_web"
    if any(term in decoder for term in ("suricata", "snort", "zeek")):
        return "ids_ndr"
    if any(term in decoder for term in ("docker", "containerd", "kubernetes", "k8s")) or _nested(event, "data.docker.container.id") or _nested(event, "data.container.id"):
        return "container_runtime"
    # A Windows event ID alone is not Sysmon. Wazuh uses the provider/channel
    # below for EventChannel events, while custom decoders commonly include
    # sysmon in their name. This prevents generic Security logins from being
    # represented as process/network Sysmon evidence.
    if "sysmon" in decoder or "sysmon" in provider or "sysmon" in channel:
        return "windows_sysmon"
    if any(term in decoder for term in ("auditd", "linux_audit")):
        return "linux_auditd"
    return "other"


def telemetry_fields(event: dict[str, Any] | None) -> tuple[str, list[str]]:
    """Return non-empty normalized field names for the decoded telemetry source."""
    source = telemetry_source(event)
    fields = event_fields(event)
    return source, sorted(key for key, value in fields.items() if value not in (None, "", []))
