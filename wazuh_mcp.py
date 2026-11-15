#!/usr/bin/env python3
"""Small dependency-free MCP server for a local Wazuh all-in-one node."""

import argparse
import datetime as dt
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional


DEFAULT_INDEXER_URL = "https://localhost:9200"
DEFAULT_ALERT_INDEX = "wazuh-alerts-4.x-*"
DEFAULT_VULN_INDEX = "wazuh-states-vulnerabilities-*"
DEFAULT_KIBANA_INDEX = ".kibana"
DEFAULT_CERT = "/etc/wazuh-indexer/certs/admin.pem"
DEFAULT_KEY = "/etc/wazuh-indexer/certs/admin-key.pem"
DEFAULT_CA = "/etc/wazuh-indexer/certs/root-ca.pem"
PROJECT_DIR = Path(__file__).resolve().parent


class OpenSearchClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("WAZUH_INDEXER_URL", DEFAULT_INDEXER_URL).rstrip("/")
        self.cert = os.getenv("WAZUH_INDEXER_CERT", DEFAULT_CERT)
        self.key = os.getenv("WAZUH_INDEXER_KEY", DEFAULT_KEY)
        self.ca = os.getenv("WAZUH_INDEXER_CA", DEFAULT_CA)
        self.alert_index = os.getenv("WAZUH_ALERT_INDEX", DEFAULT_ALERT_INDEX)
        self.vuln_index = os.getenv("WAZUH_VULN_INDEX", DEFAULT_VULN_INDEX)
        self.kibana_index = os.getenv("WAZUH_KIBANA_INDEX", DEFAULT_KIBANA_INDEX)

        ctx = ssl.create_default_context(cafile=self.ca if Path(self.ca).exists() else None)
        # Wazuh's local dashboard config uses certificate verification without
        # hostname verification; mirror that for localhost/admin-cert access.
        ctx.check_hostname = os.getenv("WAZUH_INDEXER_CHECK_HOSTNAME", "false").lower() == "true"
        if Path(self.cert).exists() and Path(self.key).exists():
            ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        self.context = ctx

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self.base_url + path
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, context=self.context, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} failed: HTTP {exc.code}: {raw[:1000]}")

    def get(self, path: str) -> Dict[str, Any]:
        return self.request("GET", path)

    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("POST", path, body)


CLIENT = OpenSearchClient()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def json_text(payload: Any) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}


def opensearch_bool_query(hours: int, min_level: int = 0, extra: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
    ]
    if min_level > 0:
        filters.append({"range": {"rule.level": {"gte": min_level}}})
    if extra:
        filters.extend(extra)
    return {"bool": {"filter": filters}}


def health_check(args: Dict[str, Any]) -> Dict[str, Any]:
    health = CLIENT.get("/_cluster/health")
    alert_count = CLIENT.get(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_count")
    vuln_count = CLIENT.get(f"/{urllib.parse.quote(CLIENT.vuln_index, safe='*-,')}/_count")
    kibana_types = CLIENT.post(
        f"/{CLIENT.kibana_index}/_search",
        {
            "size": 0,
            "aggs": {"types": {"terms": {"field": "type", "size": 50}}},
        },
    )
    return json_text(
        {
            "checked_at": now_iso(),
            "indexer_url": CLIENT.base_url,
            "cluster": {
                "name": health.get("cluster_name"),
                "status": health.get("status"),
                "nodes": health.get("number_of_nodes"),
                "active_shards_percent": health.get("active_shards_percent_as_number"),
            },
            "documents": {
                CLIENT.alert_index: alert_count.get("count"),
                CLIENT.vuln_index: vuln_count.get("count"),
            },
            "saved_object_types": kibana_types.get("aggregations", {}).get("types", {}).get("buckets", []),
        }
    )


def top_alerts(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    min_level = clamp_int(args.get("min_level"), 0, 0, 16)
    size = clamp_int(args.get("size"), 10, 1, 50)
    body = {
        "size": 0,
        "query": opensearch_bool_query(hours, min_level),
        "aggs": {
            "levels": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
            "rules": {
                "terms": {"field": "rule.id", "size": size},
                "aggs": {
                    "description": {"top_hits": {"size": 1, "_source": ["rule.description", "rule.level", "rule.groups"]}}
                },
            },
            "agents": {"terms": {"field": "agent.name", "size": size}},
            "groups": {"terms": {"field": "rule.groups", "size": size}},
            "srcips": {"terms": {"field": "data.srcip", "size": size}},
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    rules = []
    for bucket in data.get("aggregations", {}).get("rules", {}).get("buckets", []):
        hit = bucket.get("description", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
        rules.append(
            {
                "rule_id": bucket.get("key"),
                "count": bucket.get("doc_count"),
                "description": hit.get("rule", {}).get("description"),
                "level": hit.get("rule", {}).get("level"),
                "groups": hit.get("rule", {}).get("groups"),
            }
        )
    return json_text(
        {
            "window_hours": hours,
            "min_level": min_level,
            "total": data.get("hits", {}).get("total"),
            "levels": data.get("aggregations", {}).get("levels", {}).get("buckets", []),
            "top_rules": rules,
            "top_agents": data.get("aggregations", {}).get("agents", {}).get("buckets", []),
            "top_groups": data.get("aggregations", {}).get("groups", {}).get("buckets", []),
            "top_source_ips": data.get("aggregations", {}).get("srcips", {}).get("buckets", []),
        }
    )


def search_alerts(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    min_level = clamp_int(args.get("min_level"), 0, 0, 16)
    size = clamp_int(args.get("size"), 10, 1, 100)
    extra: List[Dict[str, Any]] = []
    if args.get("agent"):
        extra.append({"term": {"agent.name": str(args["agent"])}})
    if args.get("rule_id"):
        extra.append({"term": {"rule.id": str(args["rule_id"])}})
    query_text = str(args.get("text") or "").strip()
    body: Dict[str, Any] = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "data.srcip",
            "data.url",
            "location",
            "decoder.name",
        ],
        "query": opensearch_bool_query(hours, min_level, extra),
    }
    if query_text:
        body["query"] = {
            "bool": {
                "filter": opensearch_bool_query(hours, min_level, extra)["bool"]["filter"],
                "must": [
                    {
                        "simple_query_string": {
                            "query": query_text,
                            "fields": ["rule.description", "full_log", "data.url", "location", "agent.name"],
                            "default_operator": "and",
                        }
                    }
                ],
            }
        }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    hits = [{"id": hit.get("_id"), **hit.get("_source", {})} for hit in data.get("hits", {}).get("hits", [])]
    return json_text({"window_hours": hours, "min_level": min_level, "returned": len(hits), "alerts": hits})


def agent_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 30, 1, 200)
    body = {
        "size": 0,
        "query": opensearch_bool_query(hours),
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": size},
                "aggs": {
                    "max_level": {"max": {"field": "rule.level"}},
                    "critical_high": {"filter": {"range": {"rule.level": {"gte": 10}}}},
                },
            }
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    registered = []
    try:
        proc = subprocess.run(
            ["/var/ossec/bin/agent_control", "-lc"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("ID:"):
                registered.append(line)
    except Exception:
        registered = []
    agents = []
    for bucket in data.get("aggregations", {}).get("agents", {}).get("buckets", []):
        agents.append(
            {
                "agent": bucket.get("key"),
                "alerts": bucket.get("doc_count"),
                "max_rule_level": bucket.get("max_level", {}).get("value"),
                "level_10_plus": bucket.get("critical_high", {}).get("doc_count"),
            }
        )
    return json_text(
        {
            "window_hours": hours,
            "registered_agents_seen_by_manager": len(registered),
            "registered_agent_lines": registered[:size],
            "alerting_agents": agents,
        }
    )


def vulnerability_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    size = clamp_int(args.get("size"), 10, 1, 50)
    body = {
        "size": 0,
        "aggs": {
            "severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "agents": {"terms": {"field": "agent.name", "size": size}},
            "packages": {"terms": {"field": "package.name", "size": size}},
            "top_cves": {"terms": {"field": "vulnerability.id", "size": size}},
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.vuln_index, safe='*-,')}/_search", body)
    return json_text(
        {
            "index": CLIENT.vuln_index,
            "total": data.get("hits", {}).get("total"),
            "by_severity": data.get("aggregations", {}).get("severity", {}).get("buckets", []),
            "top_agents": data.get("aggregations", {}).get("agents", {}).get("buckets", []),
            "top_packages": data.get("aggregations", {}).get("packages", {}).get("buckets", []),
            "top_cves": data.get("aggregations", {}).get("top_cves", {}).get("buckets", []),
        }
    )


def nginx_filters(hours: int, location: str = "") -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]
    if location:
        filters.append({"term": {"location": location}})
    else:
        filters.append({"wildcard": {"location": "/var/log/nginx/*"}})
    return filters


def nginx_attack_category_filters() -> Dict[str, Any]:
    return {
        "Web scan / recon": {
            "bool": {
                "should": [
                    {"terms": {"rule.groups": ["web_scan", "recon"]}},
                    {"wildcard": {"rule.description": "*Multiple web server 400*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "Sensitive file probe": {
            "bool": {
                "should": [
                    {"wildcard": {"data.url": "*.env*"}},
                    {"wildcard": {"data.url": "*.git*"}},
                    {"wildcard": {"data.url": "*config*"}},
                    {"wildcard": {"data.url": "*backup*"}},
                    {"wildcard": {"data.url": "*webmail*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "WordPress / CMS": {
            "bool": {
                "should": [
                    {"wildcard": {"data.url": "*wp-login*"}},
                    {"wildcard": {"data.url": "*wp-admin*"}},
                    {"wildcard": {"data.url": "*xmlrpc*"}},
                    {"wildcard": {"rule.description": "*CMS*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "SQL injection": {
            "bool": {
                "should": [
                    {"term": {"rule.groups": "sql_injection"}},
                    {"wildcard": {"rule.description": "*SQL injection*"}},
                    {"wildcard": {"data.url": "*union*"}},
                    {"wildcard": {"data.url": "*select*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "Path traversal": {
            "bool": {
                "should": [
                    {"wildcard": {"data.url": "*../*"}},
                    {"wildcard": {"data.url": "*..%2f*"}},
                    {"wildcard": {"data.url": "*%2e%2e*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "Suspicious URL": {"wildcard": {"rule.description": "*Suspicious URL*"}},
        "Common web attack": {"wildcard": {"rule.description": "*Common web attack*"}},
        "5xx / backend error": {
            "bool": {
                "should": [
                    {"terms": {"data.id": ["500", "502", "503"]}},
                    {"term": {"rule.groups": "system_error"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "Possible successful attack": {
            "bool": {
                "filter": [
                    {"term": {"data.id": "200"}},
                    {"term": {"rule.groups": "attack"}},
                ]
            }
        },
    }


def nginx_attack_signal_query() -> Dict[str, Any]:
    return {
        "bool": {
            "should": [
                {"term": {"rule.groups": "attack"}},
                {"term": {"rule.groups": "web_scan"}},
                {"term": {"rule.groups": "recon"}},
                {"term": {"rule.groups": "sql_injection"}},
                {"wildcard": {"rule.description": "*SQL injection*"}},
                {"wildcard": {"rule.description": "*Common web attack*"}},
                {"wildcard": {"rule.description": "*Suspicious URL*"}},
                {"wildcard": {"rule.description": "*CMS*"}},
                {"wildcard": {"data.url": "*union*"}},
                {"wildcard": {"data.url": "*select*"}},
                {"wildcard": {"data.url": "*../*"}},
                {"wildcard": {"data.url": "*..%2f*"}},
                {"wildcard": {"data.url": "*%2e%2e*"}},
                {"wildcard": {"data.url": "*.env*"}},
                {"wildcard": {"data.url": "*.git*"}},
                {"wildcard": {"data.url": "*config*"}},
                {"wildcard": {"data.url": "*backup*"}},
                {"wildcard": {"data.url": "*wp-login*"}},
                {"wildcard": {"data.url": "*wp-admin*"}},
                {"wildcard": {"data.url": "*xmlrpc*"}},
            ],
            "minimum_should_match": 1,
        }
    }


def analyze_nginx_traffic(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 10, 1, 50)
    location = str(args.get("location") or "").strip()
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": nginx_filters(hours, location)}},
        "aggs": {
            "hourly": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1,
                }
            },
            "status": {"terms": {"field": "data.id", "size": 20}},
            "methods": {"terms": {"field": "data.protocol", "size": 12}},
            "rules": {"terms": {"field": "rule.description", "size": size}},
            "attack_categories": {"filters": {"filters": nginx_attack_category_filters()}},
            "levels": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
            "source_ips": {
                "terms": {"field": "data.srcip", "size": size},
                "aggs": {
                    "top_status": {"terms": {"field": "data.id", "size": 5}},
                    "top_rules": {"terms": {"field": "rule.description", "size": 3}},
                },
            },
            "urls": {"terms": {"field": "data.url", "size": size}},
            "sensitive_probe_urls": {
                "filters": {
                    "filters": {
                        ".env": {"wildcard": {"data.url": "*.env*"}},
                        ".git": {"wildcard": {"data.url": "*.git*"}},
                        "wp-login": {"wildcard": {"data.url": "*wp-login*"}},
                        "phpmyadmin": {"wildcard": {"data.url": "*phpmyadmin*"}},
                        "sdk_probe": {"wildcard": {"data.url": "*/SDK/*"}},
                        "path_traversal": {"wildcard": {"data.url": "*../*"}},
                    }
                }
            },
            "possible_successful_attack": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"rule.id": "31106"}},
                            {
                                "bool": {
                                    "filter": [
                                        {"term": {"data.id": "200"}},
                                        {"terms": {"rule.groups": ["attack", "web_scan", "recon"]}},
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    aggs = data.get("aggregations", {})
    hourly = aggs.get("hourly", {}).get("buckets", [])
    counts = [bucket.get("doc_count", 0) for bucket in hourly]
    avg = sum(counts) / len(counts) if counts else 0
    variance = sum((count - avg) ** 2 for count in counts) / len(counts) if counts else 0
    stddev = variance ** 0.5
    spike_threshold = avg + (2 * stddev)
    spikes = [
        {
            "hour": bucket.get("key_as_string"),
            "count": bucket.get("doc_count"),
            "above_average_by": round(bucket.get("doc_count", 0) - avg, 2),
        }
        for bucket in hourly
        if bucket.get("doc_count", 0) >= spike_threshold and bucket.get("doc_count", 0) > avg
    ]
    source_ips = []
    for bucket in aggs.get("source_ips", {}).get("buckets", []):
        source_ips.append(
            {
                "ip": bucket.get("key"),
                "count": bucket.get("doc_count"),
                "top_status": bucket.get("top_status", {}).get("buckets", []),
                "top_rules": bucket.get("top_rules", {}).get("buckets", []),
            }
        )
    return json_text(
        {
            "window_hours": hours,
            "location_filter": location or "/var/log/nginx/*",
            "total_events": data.get("hits", {}).get("total"),
            "hourly_average": round(avg, 2),
            "hourly_stddev": round(stddev, 2),
            "spike_threshold": round(spike_threshold, 2),
            "traffic_spikes": sorted(spikes, key=lambda item: item["count"], reverse=True)[:10],
            "status_codes": aggs.get("status", {}).get("buckets", []),
            "http_methods": aggs.get("methods", {}).get("buckets", []),
            "detection_types": aggs.get("rules", {}).get("buckets", []),
            "attack_categories": aggs.get("attack_categories", {}).get("buckets", {}),
            "rule_levels": aggs.get("levels", {}).get("buckets", []),
            "noisy_source_ips": source_ips,
            "top_target_urls": aggs.get("urls", {}).get("buckets", []),
            "sensitive_probe_counts": aggs.get("sensitive_probe_urls", {}).get("buckets", {}),
            "possible_successful_attack_events": aggs.get("possible_successful_attack", {}).get("doc_count"),
            "interpretation": [
                "404/403 volume usually indicates scanning, probing, missing paths, or blocked access attempts.",
                "5xx volume can indicate backend/application errors triggered by users or malicious payloads.",
                "Repeated events from one source IP with web_scan/recon rules are good candidates for blocking or rate limiting.",
                "200 responses paired with attack rules should be reviewed first because the request may have reached application logic.",
            ],
        }
    )


def analyze_access_anomalies(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 20, 1, 100)
    location = str(args.get("location") or "").strip()
    attack_signal = nginx_attack_signal_query()
    successful_attack = {"bool": {"filter": [{"term": {"data.id": "200"}}, attack_signal]}}
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": nginx_filters(hours, location)}},
        "aggs": {
            "total_200": {"filter": {"term": {"data.id": "200"}}},
            "successful_attack": {"filter": successful_attack},
            "successful_sqli": {
                "filter": {
                    "bool": {
                        "filter": [{"term": {"data.id": "200"}}],
                        "should": [
                            {"term": {"rule.groups": "sql_injection"}},
                            {"wildcard": {"rule.description": "*SQL injection*"}},
                            {"wildcard": {"data.url": "*union*"}},
                            {"wildcard": {"data.url": "*select*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "successful_path_traversal": {
                "filter": {
                    "bool": {
                        "filter": [{"term": {"data.id": "200"}}],
                        "should": [
                            {"wildcard": {"data.url": "*../*"}},
                            {"wildcard": {"data.url": "*..%2f*"}},
                            {"wildcard": {"data.url": "*%2e%2e*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "successful_sensitive_probe": {
                "filter": {
                    "bool": {
                        "filter": [{"term": {"data.id": "200"}}],
                        "should": [
                            {"wildcard": {"data.url": "*.env*"}},
                            {"wildcard": {"data.url": "*.git*"}},
                            {"wildcard": {"data.url": "*config*"}},
                            {"wildcard": {"data.url": "*backup*"}},
                            {"wildcard": {"data.url": "*webmail*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "source_ips": {
                "terms": {
                    "field": "data.srcip",
                    "size": size,
                    "order": [{"successful_attack.doc_count": "desc"}, {"_count": "desc"}],
                },
                "aggs": {
                    "total_200": {"filter": {"term": {"data.id": "200"}}},
                    "successful_attack": {
                        "filter": successful_attack,
                        "aggs": {
                            "top_urls": {"terms": {"field": "data.url", "size": 5}},
                            "top_rules": {"terms": {"field": "rule.description", "size": 5}},
                        },
                    },
                    "successful_sqli": {
                        "filter": {
                            "bool": {
                                "filter": [{"term": {"data.id": "200"}}],
                                "should": [
                                    {"term": {"rule.groups": "sql_injection"}},
                                    {"wildcard": {"rule.description": "*SQL injection*"}},
                                    {"wildcard": {"data.url": "*union*"}},
                                    {"wildcard": {"data.url": "*select*"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "successful_path_traversal": {
                        "filter": {
                            "bool": {
                                "filter": [{"term": {"data.id": "200"}}],
                                "should": [
                                    {"wildcard": {"data.url": "*../*"}},
                                    {"wildcard": {"data.url": "*..%2f*"}},
                                    {"wildcard": {"data.url": "*%2e%2e*"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "successful_sensitive_probe": {
                        "filter": {
                            "bool": {
                                "filter": [{"term": {"data.id": "200"}}],
                                "should": [
                                    {"wildcard": {"data.url": "*.env*"}},
                                    {"wildcard": {"data.url": "*.git*"}},
                                    {"wildcard": {"data.url": "*config*"}},
                                    {"wildcard": {"data.url": "*backup*"}},
                                    {"wildcard": {"data.url": "*webmail*"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "status_codes": {"terms": {"field": "data.id", "size": 8}},
                },
            },
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    aggs = data.get("aggregations", {})
    high_risk = []
    for bucket in aggs.get("source_ips", {}).get("buckets", []):
        total_events = bucket.get("doc_count", 0)
        total_200 = bucket.get("total_200", {}).get("doc_count", 0)
        attack_200 = bucket.get("successful_attack", {}).get("doc_count", 0)
        sqli_200 = bucket.get("successful_sqli", {}).get("doc_count", 0)
        traversal_200 = bucket.get("successful_path_traversal", {}).get("doc_count", 0)
        sensitive_200 = bucket.get("successful_sensitive_probe", {}).get("doc_count", 0)
        attack_ratio = (attack_200 / total_200) if total_200 else 0
        risk_score = min(
            100,
            round((attack_200 * 8) + (sqli_200 * 25) + (traversal_200 * 15) + (sensitive_200 * 10) + (attack_ratio * 40), 2),
        )
        if risk_score >= 70:
            risk = "high"
        elif risk_score >= 25:
            risk = "medium"
        elif attack_200:
            risk = "low"
        else:
            risk = "info"
        high_risk.append(
            {
                "source_ip": bucket.get("key"),
                "risk": risk,
                "risk_score": risk_score,
                "total_events": total_events,
                "http_200_events": total_200,
                "attack_like_http_200": attack_200,
                "attack_200_ratio": round(attack_ratio, 4),
                "sql_injection_http_200": sqli_200,
                "path_traversal_http_200": traversal_200,
                "sensitive_probe_http_200": sensitive_200,
                "top_successful_attack_urls": bucket.get("successful_attack", {}).get("top_urls", {}).get("buckets", []),
                "top_successful_attack_rules": bucket.get("successful_attack", {}).get("top_rules", {}).get("buckets", []),
                "status_codes": bucket.get("status_codes", {}).get("buckets", []),
            }
        )
    high_risk.sort(key=lambda item: (item["risk_score"], item["attack_like_http_200"], item["http_200_events"]), reverse=True)
    return json_text(
        {
            "window_hours": hours,
            "location_filter": location or "/var/log/nginx/*",
            "total_events": data.get("hits", {}).get("total"),
            "total_http_200": aggs.get("total_200", {}).get("doc_count"),
            "attack_like_http_200": aggs.get("successful_attack", {}).get("doc_count"),
            "sql_injection_http_200": aggs.get("successful_sqli", {}).get("doc_count"),
            "path_traversal_http_200": aggs.get("successful_path_traversal", {}).get("doc_count"),
            "sensitive_probe_http_200": aggs.get("successful_sensitive_probe", {}).get("doc_count"),
            "high_risk_source_ips": high_risk,
            "interpretation": [
                "HTTP 200 on attack-like requests is a strong investigation signal, not automatic proof of compromise.",
                "Prioritize IPs with SQL injection or path traversal returning 200, then review application logs and response behavior.",
                "A high normal-200 volume plus repeated attack-like-200 requests can indicate authenticated abuse, scanner bypass, or exposed routes.",
            ],
        }
    )


def auth_failed_query() -> Dict[str, Any]:
    return {"terms": {"rule.groups": ["authentication_failed", "invalid_login", "authentication_failures"]}}


def auth_success_query() -> Dict[str, Any]:
    return {"term": {"rule.groups": "authentication_success"}}


def bruteforce_query() -> Dict[str, Any]:
    return {
        "bool": {
            "should": [
                {"term": {"rule.id": "5712"}},
                {"term": {"rule.id": "5763"}},
                {"wildcard": {"rule.description": "*brute*"}},
            ],
            "minimum_should_match": 1,
        }
    }


def priority_signal_aggs() -> Dict[str, Any]:
    return {
        "high_alerts": {"filter": {"range": {"rule.level": {"gte": 10}}}},
        "failed_logins": {"filter": auth_failed_query()},
        "successful_logins": {"filter": auth_success_query()},
        "bruteforce": {"filter": bruteforce_query()},
        "attack_like_http_200": {"filter": {"bool": {"filter": [{"term": {"data.id": "200"}}, nginx_attack_signal_query()]}}},
    }


def signal_count(bucket: Dict[str, Any], name: str) -> int:
    return int(bucket.get(name, {}).get("doc_count", 0) or 0)


def host_priority_score(signals: Dict[str, int], vuln: Dict[str, int]) -> float:
    score = (
        min(35, signals.get("high_alerts", 0) * 0.08)
        + min(25, signals.get("attack_like_http_200", 0) * 3)
        + min(20, signals.get("bruteforce", 0) * 1.5)
        + min(12, signals.get("successful_logins", 0) * 0.75)
        + min(10, signals.get("failed_logins", 0) * 0.01)
        + min(18, vuln.get("critical_vulnerabilities", 0) * 0.02)
        + min(10, vuln.get("high_vulnerabilities", 0) * 0.005)
    )
    return round(min(100, score), 2)


def source_priority_score(signals: Dict[str, int]) -> float:
    score = (
        min(35, signals.get("high_alerts", 0) * 0.12)
        + min(30, signals.get("attack_like_http_200", 0) * 4)
        + min(25, signals.get("bruteforce", 0) * 2)
        + min(15, signals.get("successful_logins", 0) * 1.5)
        + min(12, signals.get("failed_logins", 0) * 0.02)
    )
    return round(min(100, score), 2)


def risk_label(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def analyze_soc_priority_queue(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 15, 1, 100)
    alert_body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]}},
        "aggs": {
            "signals": {"filters": {"filters": {
                "high_alerts": {"range": {"rule.level": {"gte": 10}}},
                "failed_logins": auth_failed_query(),
                "successful_logins": auth_success_query(),
                "bruteforce": bruteforce_query(),
                "attack_like_http_200": {"bool": {"filter": [{"term": {"data.id": "200"}}, nginx_attack_signal_query()]}},
            }}},
            "agents": {
                "terms": {"field": "agent.name", "size": size * 3},
                "aggs": {
                    **priority_signal_aggs(),
                    "top_rules": {"terms": {"field": "rule.description", "size": 3}},
                    "top_source_ips": {"terms": {"field": "data.srcip", "size": 3}},
                },
            },
            "source_ips": {
                "terms": {"field": "data.srcip", "size": size * 3},
                "aggs": {
                    **priority_signal_aggs(),
                    "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    "top_rules": {"terms": {"field": "rule.description", "size": 3}},
                },
            },
        },
    }
    vuln_body = {
        "size": 0,
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": size * 5},
                "aggs": {
                    "critical": {"filter": {"term": {"vulnerability.severity": "Critical"}}},
                    "high": {"filter": {"term": {"vulnerability.severity": "High"}}},
                    "top_cves": {"terms": {"field": "vulnerability.id", "size": 3}},
                },
            }
        },
    }
    alerts = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", alert_body)
    vulns = CLIENT.post(f"/{urllib.parse.quote(CLIENT.vuln_index, safe='*-,')}/_search", vuln_body)
    vuln_by_agent: Dict[str, Dict[str, Any]] = {}
    for bucket in vulns.get("aggregations", {}).get("agents", {}).get("buckets", []):
        vuln_by_agent[str(bucket.get("key"))] = {
            "critical_vulnerabilities": signal_count(bucket, "critical"),
            "high_vulnerabilities": signal_count(bucket, "high"),
            "top_cves": bucket.get("top_cves", {}).get("buckets", []),
        }

    host_queue = []
    for bucket in alerts.get("aggregations", {}).get("agents", {}).get("buckets", []):
        agent = str(bucket.get("key"))
        signals = {name: signal_count(bucket, name) for name in ["high_alerts", "failed_logins", "successful_logins", "bruteforce", "attack_like_http_200"]}
        vuln = vuln_by_agent.get(agent, {"critical_vulnerabilities": 0, "high_vulnerabilities": 0, "top_cves": []})
        score = host_priority_score(signals, vuln)
        host_queue.append(
            {
                "agent": agent,
                "risk": risk_label(score),
                "risk_score": score,
                "total_alert_events": bucket.get("doc_count", 0),
                **signals,
                **vuln,
                "top_rules": bucket.get("top_rules", {}).get("buckets", []),
                "top_source_ips": bucket.get("top_source_ips", {}).get("buckets", []),
            }
        )

    source_queue = []
    for bucket in alerts.get("aggregations", {}).get("source_ips", {}).get("buckets", []):
        signals = {name: signal_count(bucket, name) for name in ["high_alerts", "failed_logins", "successful_logins", "bruteforce", "attack_like_http_200"]}
        score = source_priority_score(signals)
        if score <= 0:
            continue
        source_queue.append(
            {
                "source_ip": bucket.get("key"),
                "risk": risk_label(score),
                "risk_score": score,
                "total_alert_events": bucket.get("doc_count", 0),
                **signals,
                "top_agents": bucket.get("top_agents", {}).get("buckets", []),
                "top_rules": bucket.get("top_rules", {}).get("buckets", []),
            }
        )

    host_queue.sort(key=lambda item: item["risk_score"], reverse=True)
    source_queue.sort(key=lambda item: item["risk_score"], reverse=True)
    return json_text(
        {
            "window_hours": hours,
            "total_alert_events": alerts.get("hits", {}).get("total"),
            "signal_totals": alerts.get("aggregations", {}).get("signals", {}).get("buckets", {}),
            "priority_hosts": host_queue[:size],
            "priority_source_ips": source_queue[:size],
            "interpretation": [
                "Start with critical/high hosts that combine level 10+ alerts, attack-like HTTP 200, brute force, successful logins, and Critical/High CVEs.",
                "A high source IP score means the IP is producing multiple risky signals and is a candidate for blocking or deeper review.",
                "Risk score is a triage ranking, not proof of compromise; confirm with raw events, application logs, and asset ownership.",
            ],
        }
    )


def auth_filters(hours: int, agent: str = "") -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}]
    if agent:
        filters.append({"term": {"agent.name": agent}})
    filters.append(
        {
            "bool": {
                "should": [
                    {"terms": {"rule.groups": ["authentication_failed", "authentication_success", "sshd", "pam", "sudo", "access_control"]}},
                    {"wildcard": {"location": "*auth.log*"}},
                    {"wildcard": {"location": "*secure*"}},
                    {"term": {"decoder.name": "sshd"}},
                    {"term": {"decoder.name": "pam"}},
                ],
                "minimum_should_match": 1,
            }
        }
    )
    return filters


def analyze_authentication_traffic(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 10, 1, 50)
    agent = str(args.get("agent") or "").strip()
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": auth_filters(hours, agent)}},
        "aggs": {
            "hourly": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
            "rules": {"terms": {"field": "rule.description", "size": size}},
            "levels": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
            "source_ips": {
                "terms": {"field": "data.srcip", "size": size},
                "aggs": {
                    "top_users": {"terms": {"field": "data.dstuser", "size": 5}},
                    "top_invalid_users": {"terms": {"field": "data.srcuser", "size": 5}},
                    "top_rules": {"terms": {"field": "rule.description", "size": 3}},
                    "affected_agents": {"terms": {"field": "agent.name", "size": 5}},
                },
            },
            "target_users": {"terms": {"field": "data.dstuser", "size": size}},
            "invalid_users": {"terms": {"field": "data.srcuser", "size": size}},
            "agents": {"terms": {"field": "agent.name", "size": size}},
            "locations": {"terms": {"field": "location", "size": size}},
            "decoders": {"terms": {"field": "decoder.name", "size": size}},
            "failed": {"filter": {"terms": {"rule.groups": ["authentication_failed", "invalid_login", "authentication_failures"]}}},
            "success": {"filter": {"term": {"rule.groups": "authentication_success"}}},
            "bruteforce": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"rule.id": "5712"}},
                            {"term": {"rule.id": "5763"}},
                            {"term": {"rule.id": "5551"}},
                            {"wildcard": {"rule.description": "*brute force*"}},
                            {"wildcard": {"rule.description": "*Multiple failed*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    aggs = data.get("aggregations", {})
    hourly = aggs.get("hourly", {}).get("buckets", [])
    counts = [bucket.get("doc_count", 0) for bucket in hourly]
    avg = sum(counts) / len(counts) if counts else 0
    variance = sum((count - avg) ** 2 for count in counts) / len(counts) if counts else 0
    stddev = variance ** 0.5
    threshold = avg + (2 * stddev)
    spikes = [
        {"hour": bucket.get("key_as_string"), "count": bucket.get("doc_count"), "above_average_by": round(bucket.get("doc_count", 0) - avg, 2)}
        for bucket in hourly
        if bucket.get("doc_count", 0) >= threshold and bucket.get("doc_count", 0) > avg
    ]
    source_ips = []
    for bucket in aggs.get("source_ips", {}).get("buckets", []):
        source_ips.append(
            {
                "ip": bucket.get("key"),
                "count": bucket.get("doc_count"),
                "top_target_users": bucket.get("top_users", {}).get("buckets", []),
                "top_invalid_users": bucket.get("top_invalid_users", {}).get("buckets", []),
                "top_rules": bucket.get("top_rules", {}).get("buckets", []),
                "affected_agents": bucket.get("affected_agents", {}).get("buckets", []),
            }
        )
    return json_text(
        {
            "window_hours": hours,
            "agent_filter": agent or None,
            "total_events": data.get("hits", {}).get("total"),
            "failed_events": aggs.get("failed", {}).get("doc_count"),
            "success_events": aggs.get("success", {}).get("doc_count"),
            "bruteforce_events": aggs.get("bruteforce", {}).get("doc_count"),
            "hourly_average": round(avg, 2),
            "hourly_stddev": round(stddev, 2),
            "traffic_spikes": sorted(spikes, key=lambda item: item["count"], reverse=True)[:10],
            "detection_types": aggs.get("rules", {}).get("buckets", []),
            "rule_levels": aggs.get("levels", {}).get("buckets", []),
            "noisy_source_ips": source_ips,
            "top_target_users": aggs.get("target_users", {}).get("buckets", []),
            "top_invalid_users": aggs.get("invalid_users", {}).get("buckets", []),
            "affected_agents": aggs.get("agents", {}).get("buckets", []),
            "log_sources": aggs.get("locations", {}).get("buckets", []),
            "decoders": aggs.get("decoders", {}).get("buckets", []),
            "interpretation": [
                "High authentication_failed plus repeated source IPs usually indicates SSH brute force or password spraying.",
                "Invalid/non-existent users show username enumeration attempts.",
                "Successful login events should be reviewed when close in time to failed attempts from the same IP.",
                "Root as a target user deserves priority review and should be blocked for SSH password login if possible.",
            ],
        }
    )


def analyze_ssh_bruteforce(args: Dict[str, Any]) -> Dict[str, Any]:
    hours = clamp_int(args.get("hours"), 24, 1, 720)
    size = clamp_int(args.get("size"), 10, 1, 50)
    agent = str(args.get("agent") or "").strip()
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}, {"term": {"decoder.name": "sshd"}}]
    if agent:
        filters.append({"term": {"agent.name": agent}})
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "hourly": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
            "failed": {"filter": {"terms": {"rule.groups": ["authentication_failed", "invalid_login", "authentication_failures"]}}},
            "success": {"filter": {"term": {"rule.groups": "authentication_success"}}},
            "root_targeted": {"filter": {"term": {"data.dstuser": "root"}}},
            "bruteforce": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"rule.id": "5712"}},
                            {"term": {"rule.id": "5763"}},
                            {"wildcard": {"rule.description": "*brute force*"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "source_ips": {
                "terms": {"field": "data.srcip", "size": size},
                "aggs": {
                    "target_users": {"terms": {"field": "data.dstuser", "size": 5}},
                    "invalid_users": {"terms": {"field": "data.srcuser", "size": 5}},
                    "rules": {"terms": {"field": "rule.description", "size": 5}},
                    "agents": {"terms": {"field": "agent.name", "size": 5}},
                },
            },
            "rules": {"terms": {"field": "rule.description", "size": size}},
            "target_users": {"terms": {"field": "data.dstuser", "size": size}},
            "invalid_users": {"terms": {"field": "data.srcuser", "size": size}},
            "agents": {"terms": {"field": "agent.name", "size": size}},
            "levels": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
        },
    }
    data = CLIENT.post(f"/{urllib.parse.quote(CLIENT.alert_index, safe='*-,')}/_search", body)
    aggs = data.get("aggregations", {})
    hourly = aggs.get("hourly", {}).get("buckets", [])
    counts = [bucket.get("doc_count", 0) for bucket in hourly]
    avg = sum(counts) / len(counts) if counts else 0
    stddev = (sum((count - avg) ** 2 for count in counts) / len(counts)) ** 0.5 if counts else 0
    threshold = avg + (2 * stddev)
    source_ips = []
    for bucket in aggs.get("source_ips", {}).get("buckets", []):
        source_ips.append(
            {
                "ip": bucket.get("key"),
                "count": bucket.get("doc_count"),
                "target_users": bucket.get("target_users", {}).get("buckets", []),
                "invalid_users": bucket.get("invalid_users", {}).get("buckets", []),
                "rules": bucket.get("rules", {}).get("buckets", []),
                "agents": bucket.get("agents", {}).get("buckets", []),
            }
        )
    return json_text(
        {
            "window_hours": hours,
            "agent_filter": agent or None,
            "total_ssh_events": data.get("hits", {}).get("total"),
            "failed_ssh_events": aggs.get("failed", {}).get("doc_count"),
            "successful_ssh_events": aggs.get("success", {}).get("doc_count"),
            "bruteforce_events": aggs.get("bruteforce", {}).get("doc_count"),
            "root_targeted_events": aggs.get("root_targeted", {}).get("doc_count"),
            "traffic_spikes": [
                {"hour": b.get("key_as_string"), "count": b.get("doc_count"), "above_average_by": round(b.get("doc_count", 0) - avg, 2)}
                for b in sorted(hourly, key=lambda item: item.get("doc_count", 0), reverse=True)
                if b.get("doc_count", 0) >= threshold and b.get("doc_count", 0) > avg
            ][:10],
            "top_source_ips": source_ips,
            "detection_types": aggs.get("rules", {}).get("buckets", []),
            "target_users": aggs.get("target_users", {}).get("buckets", []),
            "invalid_users": aggs.get("invalid_users", {}).get("buckets", []),
            "affected_agents": aggs.get("agents", {}).get("buckets", []),
            "rule_levels": aggs.get("levels", {}).get("buckets", []),
            "interpretation": [
                "Prioritize source IPs with high counts, repeated root attempts, and brute-force rules.",
                "Successful SSH events should be reviewed against nearby failed attempts and known admin IPs.",
                "Large data.srcuser spread suggests username spraying.",
                "Consider disabling SSH password login for root and enforcing key/MFA/VPN-only access.",
            ],
        }
    )


def backup_saved_objects(args: Dict[str, Any]) -> Dict[str, Any]:
    out_dir = Path(str(args.get("output_dir") or PROJECT_DIR / "backups"))
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_file = out_dir / f"kibana-saved-objects-{timestamp}.ndjson"
    body = {
        "size": 10000,
        "sort": [{"type": {"order": "asc"}}],
        "query": {"match_all": {}},
    }
    data = CLIENT.post(f"/{CLIENT.kibana_index}/_search", body)
    count = 0
    with out_file.open("w", encoding="utf-8") as handle:
        for hit in data.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            source["_id"] = hit.get("_id")
            source["_index"] = hit.get("_index")
            handle.write(json.dumps(source, ensure_ascii=False) + "\n")
            count += 1
    return json_text({"path": str(out_file), "objects": count})


def create_dashboard_ndjson(args: Dict[str, Any]) -> Dict[str, Any]:
    title = str(args.get("title") or "Wazuh SOC Triage").strip()[:120]
    min_level = clamp_int(args.get("min_level"), 7, 0, 16)
    out_dir = Path(str(args.get("output_dir") or PROJECT_DIR / "dashboards"))
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in title).strip("-") or "wazuh-dashboard"
    dashboard_id = f"dashboard-{slug}"
    search_id = f"search-{slug}-recent-alerts"
    out_file = out_dir / f"{slug}.ndjson"
    index_pattern_id = str(args.get("index_pattern_id") or "wazuh-alerts-*")

    search_source = {
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "filter": [{"meta": {"disabled": False, "negate": False, "alias": None, "type": "custom"}, "query": {"range": {"rule.level": {"gte": min_level}}}}],
        "query": {"query": "", "language": "kuery"},
    }
    search_object = {
        "type": "search",
        "id": search_id,
        "attributes": {
            "title": f"{title} - Recent alerts",
            "description": f"Recent Wazuh alerts with rule.level >= {min_level}",
            "hits": 0,
            "columns": ["timestamp", "agent.name", "rule.level", "rule.id", "rule.description", "data.srcip"],
            "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source, separators=(",", ":"))},
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": index_pattern_id,
            }
        ],
    }
    panels = [
        {
            "version": "7.10.2",
            "gridData": {"x": 0, "y": 0, "w": 48, "h": 28, "i": "1"},
            "panelIndex": "1",
            "embeddableConfig": {},
            "panelRefName": "panel_0",
        }
    ]
    dashboard_object = {
        "type": "dashboard",
        "id": dashboard_id,
        "attributes": {
            "title": title,
            "description": f"Generated by wazuh-mcp. Main search filters rule.level >= {min_level}.",
            "hits": 0,
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}, separators=(",", ":")),
            "panelsJSON": json.dumps(panels, separators=(",", ":")),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []}, separators=(",", ":"))},
        },
        "references": [{"name": "panel_0", "type": "search", "id": search_id}],
    }
    with out_file.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(search_object, ensure_ascii=False) + "\n")
        handle.write(json.dumps(dashboard_object, ensure_ascii=False) + "\n")
    return json_text(
        {
            "path": str(out_file),
            "objects": [{"type": "search", "id": search_id}, {"type": "dashboard", "id": dashboard_id}],
            "import_note": "Import this NDJSON from Wazuh Dashboard > Management > Dashboards Management > Saved objects > Import.",
        }
    )


TOOLS: Dict[str, Dict[str, Any]] = {
    "health_check": {
        "description": "Check Wazuh Indexer health and basic document/saved object counts.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": health_check,
    },
    "top_alerts": {
        "description": "Summarize top Wazuh alert rules, agents, groups, source IPs, and levels.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "min_level": {"type": "integer", "minimum": 0, "maximum": 16, "default": 0},
                "size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "handler": top_alerts,
    },
    "search_alerts": {
        "description": "Search recent Wazuh alerts by time window, rule level, agent, rule ID, or text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "min_level": {"type": "integer", "minimum": 0, "maximum": 16, "default": 0},
                "size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
                "agent": {"type": "string"},
                "rule_id": {"type": "string"},
                "text": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": search_alerts,
    },
    "agent_summary": {
        "description": "Summarize registered agents and agents with recent alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "size": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
            },
            "additionalProperties": False,
        },
        "handler": agent_summary,
    },
    "vulnerability_summary": {
        "description": "Summarize Wazuh vulnerability states by severity, agent, package, and CVE.",
        "inputSchema": {
            "type": "object",
            "properties": {"size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}},
            "additionalProperties": False,
        },
        "handler": vulnerability_summary,
    },
    "analyze_nginx_traffic": {
        "description": "Analyze Nginx traffic patterns captured by Wazuh: spikes, status codes, methods, source IPs, URLs, and likely attack patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "location": {
                    "type": "string",
                    "description": "Optional exact Wazuh location filter, for example /var/log/nginx/sim.co.id.access.log.",
                },
                "size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "handler": analyze_nginx_traffic,
    },
    "analyze_access_anomalies": {
        "description": "Find source IPs where HTTP 200 responses overlap with web attack signals such as SQL injection, path traversal, sensitive file probes, and suspicious URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "location": {
                    "type": "string",
                    "description": "Optional exact Wazuh location filter, for example /var/log/nginx/sim.co.id.access.log.",
                },
                "size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "additionalProperties": False,
        },
        "handler": analyze_access_anomalies,
    },
    "analyze_soc_priority_queue": {
        "description": "Rank the highest-priority hosts and source IPs by combining high alerts, attack-like HTTP 200, brute force, auth success/failure, and Critical/High vulnerability exposure.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 15},
            },
            "additionalProperties": False,
        },
        "handler": analyze_soc_priority_queue,
    },
    "analyze_authentication_traffic": {
        "description": "Analyze server authentication and SSH login patterns captured by Wazuh: failed/success logins, brute force, source IPs, users, and affected agents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "agent": {"type": "string", "description": "Optional exact agent.name filter."},
                "size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "handler": analyze_authentication_traffic,
    },
    "analyze_ssh_bruteforce": {
        "description": "Deep-dive SSH brute force patterns: failed/success SSH, root targeting, brute force rules, source IPs, usernames, and affected agents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "agent": {"type": "string", "description": "Optional exact agent.name filter."},
                "size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "handler": analyze_ssh_bruteforce,
    },
    "backup_saved_objects": {
        "description": "Back up the raw .kibana saved objects index to local NDJSON.",
        "inputSchema": {
            "type": "object",
            "properties": {"output_dir": {"type": "string", "default": "./backups"}},
            "additionalProperties": False,
        },
        "handler": backup_saved_objects,
    },
    "create_dashboard_ndjson": {
        "description": "Generate a conservative OpenSearch Dashboards NDJSON dashboard with a recent high-value Wazuh alert search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "default": "Wazuh SOC Triage"},
                "min_level": {"type": "integer", "minimum": 0, "maximum": 16, "default": 7},
                "index_pattern_id": {"type": "string", "default": "wazuh-alerts-*"},
                "output_dir": {"type": "string", "default": "./dashboards"},
            },
            "additionalProperties": False,
        },
        "handler": create_dashboard_ndjson,
    },
}


def mcp_tool_list() -> Dict[str, Any]:
    return {
        "tools": [
            {
                "name": name,
                "description": meta["description"],
                "inputSchema": meta["inputSchema"],
            }
            for name, meta in TOOLS.items()
        ]
    }


def read_message() -> Optional[Dict[str, Any]]:
    headers: Dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.decode("ascii", errors="replace").strip()
        if not line:
            break
        key, _, value = line.partition(":")
        headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    payload = sys.stdin.buffer.read(length)
    return json.loads(payload.decode("utf-8"))


def write_message(message: Dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def handle_request(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "id" not in message:
        return None
    method = message.get("method")
    params = message.get("params") or {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion") or "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "wazuh-mcp-soc", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = mcp_tool_list()
        elif method == "tools/call":
            name = params.get("name")
            if name not in TOOLS:
                raise ValueError(f"unknown tool: {name}")
            args = params.get("arguments") or {}
            result = TOOLS[name]["handler"](args)
        else:
            raise ValueError(f"unsupported method: {method}")
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32000, "message": str(exc)},
        }


def run_mcp() -> None:
    while True:
        message = read_message()
        if message is None:
            return
        response = handle_request(message)
        if response is not None:
            write_message(response)


def run_tool(name: str, args: Dict[str, Any]) -> None:
    if name not in TOOLS:
        raise SystemExit(f"Unknown tool {name!r}. Available: {', '.join(TOOLS)}")
    result = TOOLS[name]["handler"](args)
    print(result["content"][0]["text"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Wazuh MCP server")
    parser.add_argument("--tool", help="Run a tool once for testing instead of starting MCP stdio")
    parser.add_argument("--args", default="{}", help="JSON arguments for --tool")
    parsed = parser.parse_args()
    if parsed.tool:
        run_tool(parsed.tool, json.loads(parsed.args))
    else:
        run_mcp()


if __name__ == "__main__":
    main()
