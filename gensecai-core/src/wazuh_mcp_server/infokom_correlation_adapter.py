from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from mcp_server.correlation.three_sum_core import (
    evaluate_engine_a,
    tactics_for_category,
    compute_mitre_risk,
    category_default_weight,
)


DEFAULT_A_GROUPS = [
    "web",
    "attack",
    "scan",
    "recon",
    "accesslog",
]

DEFAULT_B_GROUPS = [
    "authentication_failures",
    "bruteforce",
    "blocklist",
    "zimbra",
    "spam",
    "postfix",
]

DEFAULT_C_GROUPS = [
    "firewall_drop",
    "exfiltration",
    "overflow",
    "opencti",
    "backdoor",
    "defacement",
]

SRCIP_FIELDS = [
    "data.srcip",
    "srcip",
    "source.ip",
]


def _env_bool(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _indexer_config() -> tuple[str, str, str, bool]:
    base_url = (
        os.getenv("WAZUH_INDEXER_URL")
        or "https://wazuh.indexer:9200"
    ).rstrip("/")

    username = (
        os.getenv("WAZUH_INDEXER_USER")
        or "admin"
    )

    password = (
        os.getenv("WAZUH_INDEXER_PASSWORD")
        or os.getenv("WAZUH_INDEXER_PASS")
        or ""
    )

    verify_ssl = _env_bool(
        "WAZUH_INDEXER_VERIFY_SSL",
        True,
    )

    if not password:
        raise RuntimeError(
            "WAZUH_INDEXER_PASSWORD/WAZUH_INDEXER_PASS "
            "is not configured"
        )

    return base_url, username, password, verify_ssl


def _time_filter(
    since_iso: str,
    until_iso: str,
) -> dict[str, Any]:
    # Support both field conventions.
    return {
        "bool": {
            "should": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": since_iso,
                            "lt": until_iso,
                        }
                    }
                },
                {
                    "range": {
                        "timestamp": {
                            "gte": since_iso,
                            "lt": until_iso,
                        }
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def _category_filter(
    category: str,
    groups: list[str],
    since_iso: str,
    until_iso: str,
    use_mitre: bool,
) -> dict[str, Any]:

    filters: list[dict[str, Any]] = [
        _time_filter(since_iso, until_iso),
    ]

    group_match = {
        "bool": {
            "should": [
                {"terms": {"rule.groups": groups}},
                {"terms": {"rule.groups.keyword": groups}},
            ],
            "minimum_should_match": 1,
        }
    }

    if not use_mitre:
        filters.append(group_match)

        return {
            "bool": {
                "filter": filters,
            }
        }

    tactic_terms = list(tactics_for_category(category))

    mitre_match = {
        "bool": {
            "should": [
                {
                    "terms": {
                        "rule.mitre.tactic": tactic_terms
                    }
                },
                {
                    "terms": {
                        "rule.mitre.tactic.keyword":
                        tactic_terms
                    }
                },

                # Same fallback behavior as INFOKOM:
                # groups only when alert has no MITRE data.
                {
                    "bool": {
                        "filter": [
                            group_match,
                        ],
                        "must_not": [
                            {
                                "exists": {
                                    "field":
                                    "rule.mitre.tactic"
                                }
                            },
                            {
                                "exists": {
                                    "field":
                                    "rule.mitre.id"
                                }
                            },
                        ],
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }

    filters.append(mitre_match)

    return {
        "bool": {
            "filter": filters,
        }
    }


def _score_aggs(
    use_mitre: bool,
) -> dict[str, Any]:

    aggs: dict[str, Any] = {
        "level_sum": {
            "sum": {
                "field": "rule.level",
            }
        }
    }

    if use_mitre:
        aggs["by_tactic"] = {
            "terms": {
                "field": "rule.mitre.tactic",
                "size": 32,
            },
            "aggs": {
                "level_sum": {
                    "sum": {
                        "field": "rule.level",
                    }
                }
            },
        }

        aggs["no_mitre"] = {
            "filter": {
                "bool": {
                    "must_not": [
                        {
                            "exists": {
                                "field":
                                "rule.mitre.tactic"
                            }
                        },
                        {
                            "exists": {
                                "field":
                                "rule.mitre.id"
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "level_sum": {
                    "sum": {
                        "field": "rule.level",
                    }
                }
            },
        }

    return aggs


def _score_bucket(
    bucket: dict[str, Any],
    category: str,
    use_mitre: bool,
) -> float:

    if not use_mitre:
        level_sum = (
            bucket
            .get("level_sum", {})
            .get("value", 0)
            or 0
        )

        return (
            float(level_sum)
            * category_default_weight(category)
        )

    total = 0.0

    tactic_buckets = (
        bucket
        .get("by_tactic", {})
        .get("buckets", [])
        or []
    )

    for tactic_bucket in tactic_buckets:
        level_sum = (
            tactic_bucket
            .get("level_sum", {})
            .get("value", 0)
            or 0
        )

        tactic = tactic_bucket.get("key")

        total += compute_mitre_risk(
            level_sum,
            tactic,
        )

    no_mitre_level = (
        bucket
        .get("no_mitre", {})
        .get("level_sum", {})
        .get("value", 0)
        or 0
    )

    total += (
        float(no_mitre_level)
        * category_default_weight(category)
    )

    return total


async def _post_indexer(
    body: dict[str, Any],
) -> dict[str, Any]:

    base_url, username, password, verify_ssl = (
        _indexer_config()
    )

    url = (
        f"{base_url}/"
        "wazuh-alerts-*/_search"
    )

    async with httpx.AsyncClient(
        auth=(username, password),
        verify=verify_ssl,
        timeout=30.0,
    ) as client:

        response = await client.post(
            url,
            json=body,
        )

        response.raise_for_status()

        return response.json()


async def _fetch_category(
    category: str,
    label: str,
    groups: list[str],
    since_iso: str,
    until_iso: str,
    use_mitre: bool,
) -> dict[str, Any]:

    query = _category_filter(
        category,
        groups,
        since_iso,
        until_iso,
        use_mitre,
    )

    warnings: list[str] = []

    # Try common Wazuh source-IP fields sequentially.
    for srcip_field in SRCIP_FIELDS:

        body = {
            "size": 0,
            "query": query,
            "aggs": {
                "unique_srcips": {
                    "terms": {
                        "field": srcip_field,
                        "size": 10000,
                    },
                    "aggs": _score_aggs(
                        use_mitre
                    ),
                }
            },
        }

        try:
            raw = await _post_indexer(body)
        except Exception as exc:
            warnings.append(
                f"{srcip_field}: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        buckets = (
            raw
            .get("aggregations", {})
            .get("unique_srcips", {})
            .get("buckets", [])
            or []
        )

        if not buckets:
            continue

        entries: list[tuple[str, float]] = []

        for bucket in buckets:
            ip = bucket.get("key")

            if not ip:
                continue

            score = _score_bucket(
                bucket,
                category,
                use_mitre,
            )

            entries.append(
                (
                    str(ip),
                    round(score, 2),
                )
            )

        return {
            "category": category,
            "label": label,
            "srcip_field": srcip_field,
            "entries": entries,
            "warnings": warnings,
        }

    return {
        "category": category,
        "label": label,
        "srcip_field": None,
        "entries": [],
        "warnings": warnings,
    }


async def run_three_sum_from_wazuh(
    *,
    lookback_minutes: int = 10080,
    threshold_score: int = 35,
    use_mitre: bool = True,
    category_a_groups: list[str] | None = None,
    category_b_groups: list[str] | None = None,
    category_c_groups: list[str] | None = None,
    exclude_srcips: list[str] | None = None,
    cat_a_weight: float = 1.0,
    cat_b_weight: float = 1.0,
    cat_c_weight: float = 1.0,
) -> dict[str, Any]:

    if lookback_minutes < 5:
        raise ValueError(
            "lookback_minutes must be >= 5"
        )

    if not 6 <= threshold_score <= 200:
        raise ValueError(
            "threshold_score must be between 6 and 200"
        )

    now = datetime.now(timezone.utc)
    since = now - timedelta(
        minutes=lookback_minutes
    )

    since_iso = since.isoformat()
    until_iso = now.isoformat()

    category_a_groups = (
        category_a_groups
        or DEFAULT_A_GROUPS
    )

    category_b_groups = (
        category_b_groups
        or DEFAULT_B_GROUPS
    )

    category_c_groups = (
        category_c_groups
        or DEFAULT_C_GROUPS
    )

    results = await asyncio.gather(
        _fetch_category(
            "A",
            "recon",
            category_a_groups,
            since_iso,
            until_iso,
            use_mitre,
        ),
        _fetch_category(
            "B",
            "access_anomaly",
            category_b_groups,
            since_iso,
            until_iso,
            use_mitre,
        ),
        _fetch_category(
            "C",
            "c2_exfil",
            category_c_groups,
            since_iso,
            until_iso,
            use_mitre,
        ),
    )

    by_label = {
        result["label"]: result["entries"]
        for result in results
    }

    triggers, stats = evaluate_engine_a(
        by_label.get("recon", []),
        by_label.get("access_anomaly", []),
        by_label.get("c2_exfil", []),
        threshold_score=threshold_score,
        exclude_srcips=exclude_srcips,
        cat_a_weight=cat_a_weight,
        cat_b_weight=cat_b_weight,
        cat_c_weight=cat_c_weight,
    )

    return {
        "engine":
            "INFOKOM Three-Sum Correlation",
        "mode":
            "wazuh_indexer_auto_query",

        "window": {
            "lookback_minutes":
                lookback_minutes,
            "since":
                since_iso,
            "until":
                until_iso,
        },

        "configuration": {
            "threshold_score":
                threshold_score,
            "use_mitre":
                use_mitre,

            # Technique-only STIX resolution
            # will be added in the next wave.
            "stix_technique_resolution":
                False,
        },

        "categories": {
            result["label"]: {
                "source_ip_field":
                    result["srcip_field"],
                "ip_count":
                    len(result["entries"]),
                "entries":
                    [
                        {
                            "ip": ip,
                            "score": score,
                        }
                        for ip, score
                        in result["entries"]
                    ],
                "warnings":
                    result["warnings"],
            }
            for result in results
        },

        "triggers": triggers,
        "stats": stats,
    }
