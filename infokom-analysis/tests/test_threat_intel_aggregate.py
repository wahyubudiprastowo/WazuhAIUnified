#!/usr/bin/env python3
"""Tests for unified threat intel aggregator."""
from __future__ import annotations


def test_ti_provider_result_model():
    from mcp_server.tools.threat_intel_aggregate import TIProviderResult
    r = TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="high",
                         reputation_score=100, is_malicious=True,
                         malware_families=["Emotet"], attack_techniques=["T1190"])
    assert r.provider == "crowdsec"
    assert r.is_malicious is True
    assert "Emotet" in r.malware_families
    assert "T1190" in r.attack_techniques


def test_ti_query_output_model():
    from mcp_server.tools.threat_intel_aggregate import TIQueryOutput, TIProviderResult
    r1 = TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                          indicator_type="IPv4", risk_level="high",
                          is_malicious=True)
    r2 = TIProviderResult(provider="otx", indicator="1.2.3.4",
                          indicator_type="IPv4", risk_level="medium",
                          is_malicious=True)
    out = TIQueryOutput(indicator="1.2.3.4", indicator_type="IPv4",
                        results=[r1, r2], aggregated_risk_level="high",
                        consensus_malicious=2)
    assert out.consensus_malicious == 2
    assert out.aggregated_risk_level == "high"


def test_aggregate_consensus():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="high",
                         is_malicious=True, reputation_score=90),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="medium",
                         is_malicious=True, reputation_score=60),
        TIProviderResult(provider="greynoise", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="none",
                         is_malicious=False, reputation_score=0),
        TIProviderResult(provider="virustotal", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
    ]
    out = _aggregate(results)
    assert out.consensus_malicious == 2  # crowdsec + otx
    assert out.aggregated_risk_level == "high"  # highest risk wins
    assert len(out.errors) == 1  # virustotal skipped


def test_aggregate_all_errors():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
    ]
    out = _aggregate(results)
    assert out.consensus_malicious == 0
    assert out.aggregated_risk_level is None
    assert len(out.errors) == 2


def test_input_validation_rejects_private_ip():
    from mcp_server.tools.threat_intel_aggregate import ThreatIntelAggregateInput
    from pydantic import ValidationError
    try:
        ThreatIntelAggregateInput(indicator="192.168.1.1")
        assert False, "Should have raised"
    except ValidationError:
        pass


def test_input_validation_accepts_public():
    from mcp_server.tools.threat_intel_aggregate import ThreatIntelAggregateInput
    inp = ThreatIntelAggregateInput(indicator="140.82.0.86")
    assert inp.indicator == "140.82.0.86"


def test_greynoise_404_is_unknown_not_failure():
    import asyncio
    import httpx
    from unittest.mock import AsyncMock, patch
    from mcp_server.tools import threat_intel_aggregate as module
    response = httpx.Response(404, request=httpx.Request("GET", "https://api.greynoise.io/v3/community/8.8.8.8"))
    error = httpx.HTTPStatusError("No data", request=response.request, response=response)
    with patch.object(module, "_api_call", AsyncMock(side_effect=error)):
        result = asyncio.run(module._greynoise_provider("8.8.8.8", "IPv4"))
    assert result.error is None
    assert result.detail["classification"] == "unknown"
    assert result.is_malicious is None


def test_ipv6_classification_and_scope():
    from mcp_server.threat_intel.otx import _classify_indicator
    from mcp_server.tools.threat_intel_aggregate import ThreatIntelAggregateInput
    from pydantic import ValidationError
    assert _classify_indicator("2606:4700:4700::1111") == "IPv6"
    assert _classify_indicator("999.999.999.999") == ""
    assert ThreatIntelAggregateInput(indicator="2606:4700:4700::1111")
    for value in ["::1", "fd00::1", "2001:db8::1"]:
        try:
            ThreatIntelAggregateInput(indicator=value)
            assert False, "Private/reserved IPv6 must be rejected"
        except ValidationError:
            pass


def test_otx_error_is_not_zero_pulses():
    import asyncio
    import os
    from unittest.mock import AsyncMock, patch
    from mcp_server.tools import threat_intel_aggregate as module
    with patch.dict(os.environ, {module.OTX_API_KEY_ENV: "test-only"}), patch(
        "mcp_server.threat_intel.otx._otx_request", AsyncMock(return_value={"error": "unsupported indicator"})
    ):
        result = asyncio.run(module._otx_provider("invalid", ""))
    assert result.error == "unsupported indicator"
    assert result.is_malicious is None


def test_threatfox_string_payload_is_empty_not_exception():
    import asyncio
    import os
    from unittest.mock import AsyncMock, patch
    from mcp_server.tools import threat_intel_aggregate as module
    with patch.dict(os.environ, {module.THREATFOX_API_KEY_ENV: "test-only"}), patch(
        "mcp_server.threat_intel.threatfox._threatfox_request",
        AsyncMock(return_value={"query_status": "no_results", "data": "No results"}),
    ):
        result = asyncio.run(module._threatfox_provider("101.44.160.137", "IPv4"))
    assert result.error is None
    assert result.is_malicious is False
    assert result.reputation_score == 0


if __name__ == "__main__":
    import sys, traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
