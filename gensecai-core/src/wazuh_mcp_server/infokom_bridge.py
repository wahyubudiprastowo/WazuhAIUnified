from __future__ import annotations

import inspect
from typing import Any


def _string_list(arguments: dict[str, Any], name: str) -> list[str]:
    value = arguments.get(name)
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array of strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must contain only strings")
    return value


def _positive_int(
    arguments: dict[str, Any],
    name: str,
    *,
    default: int,
    minimum: int = 1,
    maximum: int = 10000,
) -> int:
    value = arguments.get(name, default)

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value < minimum or value > maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return value


async def advanced_three_sum_correlation(
    arguments: dict,
):
    """Run INFOKOM Three-Sum directly against Wazuh Indexer."""

    from wazuh_mcp_server.infokom_correlation_adapter import (
        run_three_sum_from_wazuh,
    )

    return await run_three_sum_from_wazuh(
        lookback_minutes=int(
            arguments.get(
                "lookback_minutes",
                10080,
            )
        ),
        threshold_score=int(
            arguments.get(
                "threshold_score",
                35,
            )
        ),
        use_mitre=bool(
            arguments.get(
                "use_mitre",
                True,
            )
        ),
        category_a_groups=arguments.get(
            "category_a_groups"
        ),
        category_b_groups=arguments.get(
            "category_b_groups"
        ),
        category_c_groups=arguments.get(
            "category_c_groups"
        ),
        exclude_srcips=arguments.get(
            "exclude_srcips"
        ),
        cat_a_weight=float(
            arguments.get(
                "cat_a_weight",
                1.0,
            )
        ),
        cat_b_weight=float(
            arguments.get(
                "cat_b_weight",
                1.0,
            )
        ),
        cat_c_weight=float(
            arguments.get(
                "cat_c_weight",
                1.0,
            )
        ),
    )


async def advanced_attack_graph(
    arguments: dict[str, Any]
) -> dict[str, Any]:
    """
    Build and analyze the INFOKOM IOC attack graph.

    STIX enrichment is intentionally disabled in Wave 1 because the
    INFOKOM STIX MCP wrapper has not been merged into GenSecAI.
    """
    from mcp_server.core.attack_graph import (
        analyze_attack_graph,
        build_attack_graph,
        extract_clusters,
        suspicion_rank,
    )

    since_days = _positive_int(
        arguments,
        "since_days",
        default=30,
        maximum=365,
    )
    min_count = _positive_int(
        arguments,
        "min_count",
        default=1,
        maximum=100000,
    )
    max_iocs = _positive_int(
        arguments,
        "max_iocs",
        default=500,
        maximum=5000,
    )
    top_n = _positive_int(
        arguments,
        "top_n",
        default=10,
        maximum=100,
    )

    graph = await build_attack_graph(
        since_days=since_days,
        min_count=min_count,
        max_iocs=max_iocs,
        include_stix=False,
    )

    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    if node_count == 0:
        return {
            "engine": "INFOKOM Attack Graph",
            "nodes": 0,
            "edges": 0,
            "analysis": {},
            "suspicion_rank": [],
            "clusters": [],
        }

    analysis = analyze_attack_graph(graph, top_n=top_n)

    try:
        ranking = suspicion_rank(graph, top_n=top_n)
    except Exception as exc:
        ranking = [{"warning": f"suspicion_rank unavailable: {exc}"}]

    try:
        clusters = extract_clusters(graph)
    except Exception as exc:
        clusters = [{"warning": f"cluster extraction unavailable: {exc}"}]

    return {
        "engine": "INFOKOM Attack Graph",
        "nodes": node_count,
        "edges": edge_count,
        "analysis": analysis,
        "suspicion_rank": ranking,
        "clusters": clusters,
        "stix_enrichment": False,
    }


def _make_indicator_model(
    model_class: Any,
    indicator: str,
    extras: dict[str, Any] | None = None,
) -> Any:
    fields = getattr(model_class, "model_fields", {})

    candidate_names = (
        "ip",
        "ioc",
        "indicator",
        "search_term",
        "value",
    )

    payload: dict[str, Any] = {}

    selected = None
    for candidate in candidate_names:
        if candidate in fields:
            selected = candidate
            break

    if selected is None:
        required = [
            name
            for name, field in fields.items()
            if field.is_required()
        ]

        if len(required) == 1:
            selected = required[0]
        else:
            raise ValueError(
                f"Unable to determine indicator field for "
                f"{model_class.__name__}. Fields: {list(fields)}"
            )

    payload[selected] = indicator

    for key, value in (extras or {}).items():
        if key in fields:
            payload[key] = value

    return model_class(**payload)


async def _invoke_infokom_tool(tool: Any, parameter: Any) -> Any:
    """
    Support both normal decorated functions and MCP wrapper objects.
    """
    target = tool

    if not callable(target):
        for attr in ("fn", "func", "function", "run"):
            candidate = getattr(target, attr, None)
            if callable(candidate):
                target = candidate
                break

    if not callable(target):
        raise TypeError(
            f"INFOKOM tool object {type(tool).__name__} is not callable"
        )

    result = target(parameter)

    if inspect.isawaitable(result):
        result = await result

    return result


async def advanced_threat_intelligence(
    arguments: dict[str, Any]
) -> dict[str, Any]:
    """
    Unified INFOKOM threat-intelligence facade.

    Providers:
      - greynoise
      - crowdsec
      - threatfox
      - otx
      - cyfirma
      - all

    provider=all runs all supported providers concurrently.
    A provider failure never aborts the whole enrichment request.
    """

    import asyncio
    import json

    indicator = arguments.get("indicator")
    provider = arguments.get(
        "provider",
        "greynoise",
    )

    if (
        not isinstance(indicator, str)
        or not indicator.strip()
    ):
        raise ValueError(
            "indicator must be a non-empty string"
        )

    indicator = indicator.strip()

    if not isinstance(provider, str):
        raise ValueError(
            "provider must be a string"
        )

    provider = provider.lower().strip()

    # =========================================================
    # ALL PROVIDERS
    # =========================================================

    if provider == "all":

        providers = [
            "greynoise",
            "crowdsec",
            "threatfox",
            "otx",
            "cyfirma",
        ]

        async def _run_one(
            provider_name: str,
        ):
            try:
                child_arguments = dict(arguments)
                child_arguments["provider"] = (
                    provider_name
                )

                response = (
                    await advanced_threat_intelligence(
                        child_arguments
                    )
                )

                payload = response.get(
                    "result"
                )

                status = "success"
                error = None

                # Native provider error dictionary.
                if (
                    isinstance(payload, dict)
                    and payload.get("error")
                ):
                    status = "error"
                    error = str(
                        payload.get("error")
                    )

                # Some INFOKOM providers may return JSON
                # encoded as strings.
                elif isinstance(payload, str):
                    try:
                        parsed = json.loads(payload)

                        if (
                            isinstance(parsed, dict)
                            and parsed.get("error")
                        ):
                            status = "error"
                            error = str(
                                parsed.get("error")
                            )
                    except Exception:
                        pass

                return {
                    "provider":
                        provider_name,
                    "status":
                        status,
                    "error":
                        error,
                    "result":
                        payload,
                }

            except Exception as exc:
                return {
                    "provider":
                        provider_name,
                    "status":
                        "exception",
                    "error":
                        (
                            f"{type(exc).__name__}: "
                            f"{exc}"
                        ),
                    "result":
                        None,
                }

        results = await asyncio.gather(
            *[
                _run_one(name)
                for name in providers
            ]
        )

        provider_results = {
            item["provider"]: {
                "status":
                    item["status"],
                "error":
                    item["error"],
                "result":
                    item["result"],
            }
            for item in results
        }

        success_count = sum(
            1
            for item in results
            if item["status"] == "success"
        )

        error_count = sum(
            1
            for item in results
            if item["status"] != "success"
        )

        return {
            "engine":
                "INFOKOM Threat Intelligence",
            "provider":
                "all",
            "indicator":
                indicator,
            "summary": {
                "queried":
                    len(providers),
                "successful":
                    success_count,
                "failed":
                    error_count,
            },
            "providers":
                provider_results,
        }

    # =========================================================
    # GREYNOISE
    # =========================================================

    if provider == "greynoise":

        from mcp_server.threat_intel.greynoise import (
            GreyNoiseContextInput,
            greynoise_ip_context,
        )

        params = _make_indicator_model(
            GreyNoiseContextInput,
            indicator,
        )

        result = await _invoke_infokom_tool(
            greynoise_ip_context,
            params,
        )

    # =========================================================
    # CROWDSEC
    # =========================================================

    elif provider == "crowdsec":

        from mcp_server.threat_intel.crowdsec import (
            CrowdsecIpReputationInput,
            crowdsec_ip_reputation,
        )

        params = _make_indicator_model(
            CrowdsecIpReputationInput,
            indicator,
        )

        result = await _invoke_infokom_tool(
            crowdsec_ip_reputation,
            params,
        )

    # =========================================================
    # THREATFOX
    # =========================================================

    elif provider == "threatfox":

        from mcp_server.threat_intel.threatfox import (
            ThreatFoxSearchInput,
            threatfox_ioc_search,
        )

        params = _make_indicator_model(
            ThreatFoxSearchInput,
            indicator,
            {
                "exact_match":
                    arguments.get(
                        "exact_match",
                        False,
                    )
            },
        )

        result = await _invoke_infokom_tool(
            threatfox_ioc_search,
            params,
        )

    # =========================================================
    # ALIENVAULT OTX
    # =========================================================

    elif provider == "otx":

        from mcp_server.threat_intel.otx import (
            _classify_indicator,
            _otx_request,
            _extract_pulse_summary,
        )

        indicator_type = (
            _classify_indicator(
                indicator
            )
        )

        general = await _otx_request(
            indicator,
            "general",
        )

        pulses_raw = (
            general
            .get("pulse_info", {})
            .get("pulses", [])
            if isinstance(general, dict)
            else []
        )

        pulses = _extract_pulse_summary(
            pulses_raw
        )

        result = {
            "indicator":
                indicator,
            "indicator_type":
                indicator_type,
            "general":
                general,
            "pulses":
                pulses,
        }

    # =========================================================
    # CYFIRMA
    # =========================================================

    elif provider == "cyfirma":

        from mcp_server.threat_intel.cyfirma import (
            CyfirmaIOCInput,
            cyfirma_ioc_lookup,
        )

        params = CyfirmaIOCInput(
            indicator=indicator,
        )

        result = await cyfirma_ioc_lookup(
            params
        )

    else:
        raise ValueError(
            "provider must be one of: "
            "greynoise, crowdsec, threatfox, "
            "otx, cyfirma, all"
        )

    return {
        "engine":
            "INFOKOM Threat Intelligence",
        "provider":
            provider,
        "indicator":
            indicator,
        "result":
            result,
    }
