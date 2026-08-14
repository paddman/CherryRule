# การเชื่อม CherryRule กับ CherryWAF

## 1. Import paths

### Direct Visual Rule Studio

ใช้:

```text
dist/cherry-rules.visual-studio.json
```

มี RE2 rules จำนวน 236 กฎที่ใช้ request target รุ่นปัจจุบันได้ครบ

### Control Plane catalog

ใช้:

```text
dist/cherry-rules.bundle.json
```

Control plane ควรเก็บ rule ทั้งหมด แม้ data plane capability บางชนิดยังไม่พร้อม แล้วแสดงสถานะ:

```text
Ready
Requires Parser
Requires Stateful Engine
Requires Schema
Requires File Inspector
Requires Response Inspection
Requires Agent Gateway
```

## 2. Target mapping

| CherryRule | GUI เดิม |
|---|---|
| `request.method` | `method` |
| `request.path` | `path` |
| `request.query` | `query` |
| `request.body` | `body` |
| `request.headers` | `headers` |
| `request.cookies` | `cookies` |
| `client.ip` | เพิ่ม target `source_ip` |
| `upload.filename` | เพิ่ม target `upload_filename` |
| `response.body` | เพิ่ม response phase |

## 3. Data model ที่ควรเพิ่มในฐานข้อมูล

```text
rules
rule_versions
rule_targets
rule_transforms
rule_scopes
rule_exclusions
rule_tests
rule_deployments
rule_metrics
rule_audit
indicator_sets
indicator_items
application_profiles
```

## 4. API ที่แนะนำ

```text
GET    /api/v1/rule-packs
POST   /api/v1/rule-packs/import
GET    /api/v1/rules
POST   /api/v1/rules/test
POST   /api/v1/rules/replay
POST   /api/v1/rules/{id}/stage
POST   /api/v1/rules/{id}/publish
POST   /api/v1/rules/{id}/rollback
GET    /api/v1/rules/{id}/metrics
POST   /api/v1/exclusions
GET    /api/v1/capabilities
```

## 5. Publish validation

ก่อน publish:

```text
schema validation
ID uniqueness
RE2 compilation
target capability check
transform capability check
fixture execution
application scope
approval policy
data-plane dry run
atomic config generation
reload health check
```

## 6. Score fields

Event schema ควรแยก:

```json
{
  "native_score": 10,
  "crs_anomaly_score": 5,
  "behavior_score": 20,
  "reputation_score": 0,
  "decision": "block",
  "matched_rules": ["CWAF-INJ-220001", "CRS-942100"]
}
```

## 7. Compatibility

CherryRule ไม่ควรฝัง implementation ของ Coraza/ModSecurity ลงใน source catalog โดยตรง ให้ compiler adapter เป็นผู้แปลง:

```text
CherryRule → Coraza/ModSecurity adapter
CherryRule → native Go matcher
CherryRule → Envoy/Proxy-Wasm adapter
CherryRule → UI simulation engine
```

source of truth จึงไม่ถูกผูกตายกับ data plane ตัวเดียว
