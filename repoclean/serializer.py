import json
from dataclasses import asdict


def to_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def scanresult_to_dict(result):
    d = asdict(result)
    d["repo_path"] = str(result.repo_path).replace("\\", "/")
    d["junk_dirs"] = [p.replace("\\", "/") for p in d["junk_dirs"]]
    d["junk_files"] = [p.replace("\\", "/") for p in d["junk_files"]]
    d["large_files"] = [{"path": p.replace("\\", "/"), "bytes": size} for (p, size) in result.large_files]
    return d


def secrets_to_dict(findings):
    return {
        "count": len(findings),
        "findings": [
            {
                **asdict(f),
                "file": f.file.replace("\\", "/")
            }
            for f in findings
        ]
    }
