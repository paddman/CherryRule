#!/usr/bin/env python3
"""Validate CherryRule and emit a clean corpus with Thai explanations for every rule."""

from __future__ import annotations

import collections
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import jsonschema
import re2
import yaml

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "dist" / "cherry-rules.bundle.yaml"
GENERATED_JSON_PATH = ROOT / "dist" / "cherry-rules.re2-catalog.json"
SCHEMA_PATH = ROOT / "schema" / "cherry-rule-pack.schema.json"
OUT_DIR = ROOT / "audit"

THAI_RE = re.compile(r"[\u0E00-\u0E7F]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

CATEGORY_ROOT_TH = {
    "protocol": "ความผิดปกติของโปรโตคอล HTTP",
    "routing": "การกำหนดเส้นทางและ Host",
    "cache": "การโจมตีระบบแคช",
    "injection": "การแทรกคำสั่งหรือข้อมูลอันตราย",
    "rce": "การพยายามรันคำสั่งบนเซิร์ฟเวอร์",
    "xml": "การโจมตีข้อมูล XML",
    "deserialization": "การ deserialize ข้อมูลที่ไม่ปลอดภัย",
    "traversal": "การเข้าถึงไฟล์นอกขอบเขต",
    "ssrf": "การบังคับเซิร์ฟเวอร์ให้เชื่อมต่อปลายทางอื่น",
    "exposure": "การเปิดเผยไฟล์ ข้อมูล หรือ endpoint สำคัญ",
    "upload": "การอัปโหลดไฟล์ที่เสี่ยงอันตราย",
    "auth": "การโจมตีกระบวนการยืนยันตัวตน",
    "session": "ความผิดปกติของ session และ cookie",
    "token": "ความผิดปกติของ token",
    "oauth": "ความเสี่ยงใน OAuth และ OIDC",
    "api": "การโจมตีหรือใช้งาน API ผิดรูปแบบ",
    "business": "การใช้งานกระบวนการธุรกิจในทางที่ผิด",
    "abuse": "พฤติกรรมอัตโนมัติหรือการใช้งานเกินขอบเขต",
    "recon": "การสแกนและสำรวจระบบ",
    "behavior": "พฤติกรรมต่อเนื่องที่มีความเสี่ยง",
    "platform": "การโจมตีแพลตฟอร์มและเฟรมเวิร์ก",
    "cloud": "ความเสี่ยงของบริการคลาวด์",
    "devops": "ความเสี่ยงของระบบ DevOps และ orchestration",
    "response": "ข้อมูลอันตรายหรือข้อมูลลับใน response",
    "privacy": "การรั่วไหลของข้อมูลส่วนบุคคล",
    "ai": "การโจมตีระบบ AI, LLM และ agent",
    "threat-intel": "การบังคับใช้งานข้อมูลข่าวกรองภัยคุกคาม",
    "virtual-patch": "วงจรการทำงานของ virtual patch",
}

PHASE_TH = {
    "connection": "เริ่มต้นการเชื่อมต่อ",
    "request_headers": "ส่วนหัวของคำขอ",
    "request_uri": "URI และเส้นทางของคำขอ",
    "request_body": "เนื้อหาของคำขอ",
    "response_headers": "ส่วนหัวของคำตอบ",
    "response_body": "เนื้อหาของคำตอบ",
}

ENGINE_TH = {
    "re2": "RE2 regular expression",
    "parser": "ตัวแยกโครงสร้างโปรโตคอล",
    "policy": "นโยบายแบบกำหนดเงื่อนไข",
    "stateful": "การวิเคราะห์แบบเก็บสถานะหลายคำขอ",
    "schema": "การตรวจ schema",
    "token_parser": "ตัวแยกและตรวจ token",
    "file_inspector": "ตัวตรวจสอบไฟล์",
    "response_policy": "นโยบายตรวจ response",
    "reputation": "ข้อมูลชื่อเสียงและ threat intelligence",
    "dns_policy": "นโยบาย DNS และการ resolve ปลายทาง",
    "authorization": "การตรวจสิทธิ์การเข้าถึง",
    "graphql": "ตัววิเคราะห์ GraphQL",
    "websocket": "ตัววิเคราะห์ WebSocket",
    "grpc": "ตัววิเคราะห์ gRPC",
    "signature": "ลายเซ็นดิจิทัลหรือ fingerprint",
    "agent_gateway": "นโยบายควบคุม AI agent และเครื่องมือ",
    "catalog": "การตรวจความถูกต้องของ catalog",
    "deployment": "การควบคุมการนำกฎขึ้นใช้งาน",
}

ACTION_TH = {
    "score": "เพิ่มคะแนนความเสี่ยงเพื่อให้ระบบตัดสินร่วมกับสัญญาณอื่น",
    "block": "บล็อกคำขอหรือคำตอบที่ตรงเงื่อนไข",
    "challenge": "ส่ง challenge เพื่อแยกผู้ใช้จริงออกจาก bot",
    "throttle": "จำกัดอัตราหรือชะลอการใช้งาน",
    "sanitize": "ทำความสะอาดค่าที่เสี่ยงก่อนส่งต่อ",
    "redact": "ปกปิดข้อมูลสำคัญก่อนส่งคำตอบ",
    "allow": "อนุญาตตามข้อยกเว้นที่กำหนด",
}

SEVERITY_TH = {
    "info": "ข้อมูลประกอบ",
    "low": "ต่ำ",
    "medium": "ปานกลาง",
    "high": "สูง",
    "critical": "วิกฤต",
}

CONFIDENCE_TH = {
    "low": "ต่ำ ต้องใช้หลักฐานอื่นยืนยันเพิ่มเติม",
    "medium": "ปานกลาง ควรตรวจบริบทของระบบร่วมด้วย",
    "high": "สูง แต่ยังไม่ถือเป็นคำตัดสินว่าโจมตีสำเร็จ",
}

TARGET_TH = {
    "request.method": "HTTP method",
    "request.path": "เส้นทาง URL",
    "request.uri": "URI ของคำขอ",
    "request.query": "query string",
    "request.body": "เนื้อหา request body",
    "request.headers": "ส่วนหัวของคำขอ",
    "request.cookies": "cookie ของคำขอ",
    "response.headers": "ส่วนหัวของคำตอบ",
    "response.body": "เนื้อหาของคำตอบ",
    "response.status": "สถานะ HTTP ของคำตอบ",
    "client.ip": "IP ของไคลเอนต์",
    "client.fingerprint": "fingerprint ของไคลเอนต์",
    "tls.fingerprint": "TLS fingerprint",
    "file.name": "ชื่อไฟล์",
    "file.content": "เนื้อหาไฟล์",
    "file.metadata": "metadata ของไฟล์",
    "token": "token ที่ส่งมากับคำขอ",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def error_path(error: jsonschema.ValidationError) -> str:
    if not error.absolute_path:
        return "$"
    return "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}"
        for part in error.absolute_path
    )


def thai_list(values: list[str]) -> str:
    if not values:
        return "ข้อมูลที่ engine กำหนด"
    labels = [TARGET_TH.get(value, value.replace(".", " ")) for value in values]
    if len(labels) == 1:
        return labels[0]
    return ", ".join(labels[:-1]) + " และ " + labels[-1]


def operator_explanation_th(rule: dict[str, Any]) -> str:
    operator = rule.get("operator")
    targets = thai_list([str(value) for value in rule.get("targets", [])])
    transforms = [str(value) for value in rule.get("transforms", [])]
    transform_text = ", ".join(transforms) if transforms else "ไม่มีการแปลงค่าเพิ่มเติม"
    if not isinstance(operator, dict):
        return f"ตรวจ {targets} ตามเงื่อนไขของ engine โดยตรง"

    operator_type = str(operator.get("type", "unknown"))
    if operator_type == "regex":
        pattern = str(operator.get("pattern", ""))
        return (
            f"นำ {targets} ผ่านขั้นตอนแปลงค่า {transform_text} แล้วเทียบด้วย RE2 pattern "
            f"`{pattern}` การ match หมายถึงพบรูปแบบที่กฎสนใจ ไม่ได้ยืนยันว่าโจมตีสำเร็จ"
        )

    check = operator.get("check")
    params = operator.get("params")
    details: list[str] = []
    if check:
        details.append(f"check `{check}`")
    if params:
        details.append(
            "พารามิเตอร์ " + json.dumps(params, ensure_ascii=False, sort_keys=True)
        )
    detail_text = " พร้อม " + " และ ".join(details) if details else ""
    return (
        f"ตรวจ {targets} ด้วย operator `{operator_type}`{detail_text} "
        "โดยให้ engine วิเคราะห์โครงสร้างหรือสถานะที่ regex เพียงอย่างเดียวตรวจไม่ได้"
    )


def build_explanation_th(rule: dict[str, Any]) -> dict[str, str]:
    rule_id = str(rule.get("id", "ไม่ทราบรหัส"))
    category = str(rule.get("category", "unknown"))
    category_root = category.split(".", 1)[0]
    category_th = CATEGORY_ROOT_TH.get(category_root, f"หมวด {category}")
    phase = str(rule.get("phase", "unknown"))
    phase_th = PHASE_TH.get(phase, phase)
    engine = str(rule.get("engine", "unknown"))
    engine_th = ENGINE_TH.get(engine, engine)
    severity = str(rule.get("severity", "unknown"))
    severity_th = SEVERITY_TH.get(severity, severity)
    confidence = str(rule.get("confidence", "unknown"))
    confidence_th = CONFIDENCE_TH.get(confidence, confidence)
    action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
    action_mode = str(action.get("mode", "unknown"))
    action_th = ACTION_TH.get(action_mode, f"ดำเนินการแบบ {action_mode}")
    score = action.get("score", 0)
    targets = thai_list([str(value) for value in rule.get("targets", [])])
    false_positive = rule.get("false_positive_notes")
    if not isinstance(false_positive, str) or not false_positive.strip():
        false_positive = (
            "อาจเกิด false positive ได้เมื่อแอปพลิเคชันมี endpoint, payload, bot, scanner "
            "หรือ workflow ที่ตั้งใจใช้รูปแบบเดียวกับเงื่อนไขของกฎ"
        )
    requirements = rule.get("requirements")
    requirement_text = (
        ", ".join(str(value) for value in requirements)
        if isinstance(requirements, list) and requirements
        else "ไม่มี requirement เพิ่มเติมนอกเหนือจากข้อมูลที่ target ระบุ"
    )
    enabled_text = "เปิดใช้งานโดยค่าเริ่มต้น" if rule.get("default_enabled") else "ปิดโดยค่าเริ่มต้น"

    return {
        "summary": (
            f"กฎ {rule_id} ใช้ตรวจจับ{category_th}จาก {targets} ในช่วง{phase_th} "
            f"โดยใช้{engine_th}"
        ),
        "detection_logic": operator_explanation_th(rule),
        "risk_and_impact": (
            f"ระดับความรุนแรง {severity_th} และความเชื่อมั่น {confidence_th} "
            "หากเป็นการโจมตีจริง ผลกระทบขึ้นกับสิทธิ์ของระบบ ปลายทางที่เข้าถึงได้ "
            "และว่าคำขอผ่านชั้นป้องกันอื่นหรือไม่"
        ),
        "enforcement": (
            f"เมื่อเข้าเงื่อนไข ระบบจะ{action_th} ค่า score ของกฎคือ {score} และกฎนี้{enabled_text}"
        ),
        "false_positive": str(false_positive).strip(),
        "requirements": requirement_text,
        "tuning": (
            "ตรวจ event จริงเทียบกับ application log และ asset owner ก่อนปรับเป็น block "
            "จากนั้นจำกัด scope ตามโดเมน เส้นทาง method ชนิดเนื้อหา หรือผู้ใช้ที่เกี่ยวข้อง "
            "อย่าปิดทั้งกฎเพราะตัวอย่างเดียว และบันทึกเหตุผลของข้อยกเว้นทุกครั้ง"
        ),
        "validation": (
            "ให้ยืนยันด้วย request/response ที่ถูก redaction, correlation ID, log จากปลายทาง "
            "และพฤติกรรมต่อเนื่อง การ match เพียงครั้งเดียวเป็นสัญญาณตรวจจับ ไม่ใช่หลักฐานว่าเครื่องถูกยึดหรือข้อมูลรั่วแล้ว"
        ),
    }


def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)

    bundle = yaml.safe_load(BUNDLE_PATH.read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        raise SystemExit("bundle root must be a mapping")

    raw_rules = bundle.get("rules")
    packs = bundle.get("packs")
    if not isinstance(raw_rules, list):
        raise SystemExit("bundle.rules must be a list")
    if not isinstance(packs, list):
        raise SystemExit("bundle.packs must be a list")

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    rule_schema = schema["$defs"]["rule"]
    validator = jsonschema.Draft202012Validator(rule_schema)

    declared_total = bundle.get("total_rules")
    declared_pack_total = sum(int(pack.get("rule_count", 0)) for pack in packs)
    top_level_errors: list[str] = []
    if declared_total != len(raw_rules):
        top_level_errors.append(
            f"bundle total_rules={declared_total!r} but rules has {len(raw_rules)} entries"
        )
    if declared_pack_total != len(raw_rules):
        top_level_errors.append(
            f"pack rule_count sum={declared_pack_total} but rules has {len(raw_rules)} entries"
        )

    id_counts = collections.Counter(
        rule.get("id") for rule in raw_rules if isinstance(rule, dict)
    )
    duplicate_ids = sorted(
        str(rule_id) for rule_id, count in id_counts.items() if rule_id and count > 1
    )

    pack_for_index: list[dict[str, Any]] = []
    for pack in packs:
        for _ in range(int(pack.get("rule_count", 0))):
            pack_for_index.append(pack)

    valid_rules: list[dict[str, Any]] = []
    invalid_rules: list[dict[str, Any]] = []
    localization_gaps: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    engine_counts: collections.Counter[str] = collections.Counter()
    severity_counts: collections.Counter[str] = collections.Counter()
    action_counts: collections.Counter[str] = collections.Counter()
    category_counts: collections.Counter[str] = collections.Counter()
    native_thai_total = 0
    generated_thai_total = 0
    re2_checked = 0
    re2_failed = 0

    for index, raw_rule in enumerate(raw_rules):
        issues: list[str] = []
        rule_warnings: list[str] = []
        rule_id = f"index:{index}"

        if not isinstance(raw_rule, dict):
            invalid_rules.append(
                {"index": index, "id": rule_id, "errors": ["rule is not an object"]}
            )
            continue

        rule_id = str(raw_rule.get("id") or rule_id)
        validation_errors = sorted(
            validator.iter_errors(raw_rule),
            key=lambda item: ("/".join(map(str, item.absolute_path)), item.message),
        )
        for validation_error in validation_errors:
            issues.append(f"{error_path(validation_error)}: {validation_error.message}")

        if rule_id in duplicate_ids:
            issues.append("duplicate rule id")

        for field in ("name", "name_th", "description_th", "false_positive_notes"):
            value = raw_rule.get(field)
            if isinstance(value, str):
                if CONTROL_RE.search(value):
                    issues.append(f"{field} contains a control character")
                if value != value.strip():
                    rule_warnings.append(f"{field} has leading or trailing whitespace")

        operator = raw_rule.get("operator")
        if isinstance(operator, dict) and operator.get("type") == "regex":
            pattern = operator.get("pattern")
            if isinstance(pattern, str):
                re2_checked += 1
                try:
                    re2.compile(pattern)
                except Exception as exc:  # google-re2 uses implementation-specific errors
                    re2_failed += 1
                    issues.append(f"RE2 compile failed: {exc}")

        if issues:
            invalid_rules.append({"index": index, "id": rule_id, "errors": issues})
            continue

        normalized = dict(raw_rule)
        name_th = normalized.get("name_th")
        description_th = normalized.get("description_th")
        thai_name_ok = isinstance(name_th, str) and bool(THAI_RE.search(name_th))
        thai_description_ok = isinstance(description_th, str) and bool(
            THAI_RE.search(description_th)
        )
        explanation_th = build_explanation_th(normalized)

        if thai_name_ok and thai_description_ok:
            localization_status = "native"
            native_thai_total += 1
        else:
            localization_status = "generated"
            generated_thai_total += 1
            localization_gaps.append(
                {
                    "index": index,
                    "id": rule_id,
                    "source_name_th": name_th,
                    "source_description_th": description_th,
                }
            )
            normalized["source_name_th"] = name_th
            normalized["source_description_th"] = description_th
            normalized["name_th"] = (
                f"ตรวจจับ{CATEGORY_ROOT_TH.get(str(normalized.get('category', '')).split('.', 1)[0], 'พฤติกรรมตามกฎ')} "
                f"ตามกฎ {rule_id}"
            )
            normalized["description_th"] = explanation_th["summary"]

        pack = pack_for_index[index] if index < len(pack_for_index) else {}
        normalized["source_pack"] = {
            "id": pack.get("id"),
            "slug": pack.get("slug"),
            "version": pack.get("version"),
        }
        normalized["localization"] = {
            "status": localization_status,
            "language": "th",
            "explanation_generated": True,
        }
        normalized["explanation_th"] = explanation_th
        valid_rules.append(normalized)

        engine_counts[str(raw_rule.get("engine"))] += 1
        severity_counts[str(raw_rule.get("severity"))] += 1
        category_counts[str(raw_rule.get("category"))] += 1
        action = raw_rule.get("action")
        if isinstance(action, dict):
            action_counts[str(action.get("mode"))] += 1

        if rule_warnings:
            warnings.append({"index": index, "id": rule_id, "warnings": rule_warnings})

    generated_json_status: dict[str, Any]
    try:
        generated_json = json.loads(GENERATED_JSON_PATH.read_text(encoding="utf-8"))
        generated_json_status = {
            "parseable": True,
            "root_type": type(generated_json).__name__,
        }
    except Exception as exc:
        generated_json_status = {
            "parseable": False,
            "error": f"{type(exc).__name__}: {exc}",
            "ignored": True,
            "reason": "the clean corpus is regenerated from the validated YAML bundle",
        }

    source = {
        "repository": "paddman/CherryRule",
        "ref": "recovery/catalog-source-20260814",
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "bundle_path": str(BUNDLE_PATH.relative_to(ROOT)),
        "bundle_sha256": sha256(BUNDLE_PATH),
        "schema_sha256": sha256(SCHEMA_PATH),
    }
    report = {
        "audit_version": "1.1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": source,
        "declared_total": declared_total,
        "observed_total": len(raw_rules),
        "valid_total": len(valid_rules),
        "invalid_total": len(invalid_rules),
        "native_thai_total": native_thai_total,
        "generated_thai_total": generated_thai_total,
        "thai_explainable_total": len(valid_rules),
        "duplicate_ids": duplicate_ids,
        "top_level_errors": top_level_errors,
        "re2": {
            "regex_rules_checked": re2_checked,
            "compile_failures": re2_failed,
        },
        "generated_re2_catalog_json": generated_json_status,
        "counts": {
            "engine": dict(sorted(engine_counts.items())),
            "severity": dict(sorted(severity_counts.items())),
            "action": dict(sorted(action_counts.items())),
            "category": dict(sorted(category_counts.items())),
        },
        "invalid_rules": invalid_rules,
        "localization_gaps": localization_gaps,
        "warnings": warnings,
    }
    clean_corpus = {
        "schema_version": "1.0",
        "catalog_version": bundle.get("catalog_version"),
        "generated_at": bundle.get("generated_at"),
        "source": source,
        "total_rules": len(valid_rules),
        "native_thai_rules": native_thai_total,
        "generated_thai_rules": generated_thai_total,
        "packs": packs,
        "rules": valid_rules,
    }

    (OUT_DIR / "catalog-validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (OUT_DIR / "cherry-rules.valid.json").write_text(
        json.dumps(clean_corpus, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    summary = {
        key: report[key]
        for key in (
            "declared_total",
            "observed_total",
            "valid_total",
            "invalid_total",
            "native_thai_total",
            "generated_thai_total",
            "thai_explainable_total",
            "duplicate_ids",
            "top_level_errors",
            "re2",
            "generated_re2_catalog_json",
        )
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    return 1 if top_level_errors or invalid_rules else 0


if __name__ == "__main__":
    raise SystemExit(main())
