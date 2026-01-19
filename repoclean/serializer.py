import json
from dataclasses import asdict


def to_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def scanresult_to_dict(result):
    d = asdict(result)

    d["repo_path"] = str(result.repo_path).replace("\\", "/")

    d["junk_dirs"] = [p.replace("\\", "/") for p in d.get("junk_dirs", [])]
    d["junk_files"] = [p.replace("\\", "/") for p in d.get("junk_files", [])]
    d["sensitive_files"] = [p.replace("\\", "/") for p in d.get("sensitive_files", [])]

    d["tracked_junk"] = [p.replace("\\", "/") for p in d.get("tracked_junk", [])]

    d["large_files"] = [
        {"path": p.replace("\\", "/"), "bytes": size}
        for (p, size) in getattr(result, "large_files", [])
    ]

    d["gitignore_missing"] = bool(d.get("gitignore_missing", False))
    d["env_unignored"] = bool(d.get("env_unignored", False))
    d["repo_health_score"] = int(d.get("repo_health_score", 0))

    return d


def secrets_to_dict(findings):
    return {
        "count": len(findings),
        "findings": [
            {
                **asdict(f),
                "file": f.file.replace("\\", "/"),
            }
            for f in findings
        ],
    }


def trackedjunk_to_dict(result):
    d = asdict(result)
    d["repo_path"] = str(result.repo_path).replace("\\", "/")
    d["tracked_junk"] = [p.replace("\\", "/") for p in d.get("tracked_junk", [])]
    return d

def gate_to_dict(payload: dict) -> dict:
    """
    Gate payload is already dict-like but we normalize paths to posix.
    """
    def _posix(s):
        return (s or "").replace("\\", "/")

    out = dict(payload)

    if "repo_path" in out:
        out["repo_path"] = _posix(out["repo_path"])

    if "actions" in out and isinstance(out["actions"], list):
        out["actions"] = [str(x) for x in out["actions"]]

    if "suggestions" in out and isinstance(out["suggestions"], list):
        out["suggestions"] = [str(x) for x in out["suggestions"]]

    return out
