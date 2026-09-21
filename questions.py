from typesafe_sdk import Choice, Noul, Score


def build_questions() -> dict:
    """JEV questions for one payload. Keep all questions in a single system_one call."""
    return {
        "is_attack": Noul(
            instructions=(
                "The input is a web-attack payload against an application or API, "
                "not ordinary business data, a username, a search query, or a normal JSON/XML document."
            ),
            criteria={
                "true": (
                    "Exploit syntax or attack intent: XSS, SQL injection, XXE, command injection, "
                    "path traversal, SSRF, SSTI, file inclusion, or similar."
                ),
                "false": (
                    "Harmless user/business input, including names, product search, comments, "
                    "normal JSON/XML, or encoded text without exploit structure."
                ),
            },
        ),
        "attack_type": Choice(
            instructions=(
                "Primary attack family of this payload. Choose benign if it is not an attack. "
                "If several families appear, pick the one that would execute first."
            ),
            criteria={
                "xss": (
                    "Cross-site scripting: script tags, event handlers, javascript: URLs, "
                    "svg/onload, template literals into HTML/JS sinks."
                ),
                "sql_injection": (
                    "SQL injection: tautologies, UNION SELECT, stacked queries, comment bypass, "
                    "quote breaking, time/boolean-based probes."
                ),
                "xxe": (
                    "XML External Entity: DOCTYPE, ENTITY SYSTEM/PUBLIC, parameter entities, "
                    "external DTD fetching."
                ),
                "command_injection": (
                    "OS command injection: shell metacharacters, command chaining, reverse-shell style input."
                ),
                "path_traversal": (
                    "Directory traversal: ../ sequences, encoded dots, /etc/passwd, Windows \\..\\ paths."
                ),
                "ssrf": (
                    "Server-side request forgery: internal/link-local IPs, cloud metadata URLs, "
                    "file:// or gopher:// used to hit internal services."
                ),
                "ssti": (
                    "Server-side template injection: {{ }}, ${}, <%% %>, Twig/Jinja/Freemarker expressions."
                ),
                "file_inclusion": (
                    "Local/remote file inclusion: php wrappers, expected include of remote/local files."
                ),
                "deserialization": (
                    "Insecure deserialization gadgets or serialized object blobs used as an exploit."
                ),
                "other_attack": "A web exploit attempt that does not fit the labels above.",
                "benign": "Normal non-malicious input with no exploit intent.",
            },
        ),
        "severity": Score(
            instructions="Potential impact if this payload reached a vulnerable application.",
            criteria=[
                "Not an attack / no impact",
                "Low: noisy probe, limited impact",
                "Medium: likely XSS, SQLi, XXE, or data leak",
                "High: likely RCE, auth bypass, or large-scale data theft",
            ],
        ),
        "should_block": Noul(
            instructions="A production WAF or API gateway should block this request instead of allowing it.",
            criteria={
                "true": "High-confidence exploit payload that is unsafe to forward to the origin.",
                "false": "Allow or only monitor; ordinary traffic or too ambiguous to auto-block.",
            },
        ),
    }
