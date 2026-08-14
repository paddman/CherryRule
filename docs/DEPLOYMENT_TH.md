# Deployment และ False Positive Tuning

## 1. ห้ามเปิด block ทั้ง catalog ในครั้งเดียว

ลำดับมาตรฐาน:

```text
Validate
→ Replay traffic
→ Learning / Detect only
→ Review top matches
→ Add narrow exclusions
→ Canary by application/tenant
→ Block high-confidence rules
→ Raise anomaly enforcement
→ Monitor and rollback
```

## 2. Learning phase

เก็บอย่างน้อย:

- request count
- match count ต่อ rule/application/route/parameter
- unique clients
- response status delta
- origin latency
- false-positive disposition
- top evidence แบบ redact
- CPU time และ body bytes inspected

## 3. Exclusion ที่ดี

```yaml
rule_id: CWAF-INJ-220038
application: cms-prod
route: POST /articles
target: request.body
parameter: content
reason: rich HTML editor
expires_at: 2026-11-01
owner: appsec
```

Exclusion ที่แย่:

```yaml
category: injection.xss
application: '*'
disabled: true
```

แบบหลังเงียบดีมาก เพราะระบบไม่ตรวจอะไรแล้ว

## 4. Threshold

ค่าตั้งต้น:

```text
balanced inbound  = 10
balanced outbound = 8
strict inbound    = 7
strict outbound   = 6
```

Immediate block ไม่ควรผ่าน threshold:

- malformed request framing
- duplicate/conflicting Content-Length
- exact sensitive file
- executable upload
- private key marker
- token signature invalid
- authorization binding failure
- webhook signature/replay failure

## 5. Platform rules

กฎ WordPress/Drupal/Joomla/Magento/Admin UI ต้องอ่าน `application.technology_profile`

```text
non-WordPress + /wp-login.php → recon score
WordPress + /wp-login.php     → auth rate/challenge
```

## 6. Virtual patch

Virtual patch ต้องระบุ:

```yaml
affected_product: example-server
affected_versions: '>=1.0.0,<1.4.7'
paths: [/api/import]
methods: [POST]
expires_at: 2026-09-15
deployment: detect
rollback_rule_version: 3
```

เปลี่ยนเป็น block หลัง positive/negative fixtures และ canary ผ่านเท่านั้น

## 7. Rollback triggers

- 5xx เพิ่มเกิน baseline
- authentication success ลดผิดปกติ
- checkout/payment conversion ลด
- origin latency p95 เพิ่มเกินงบ
- match rate กระโดดหลัง deploy
- customer/application owner ยืนยัน false positive

## 8. Metrics ที่ UI ควรแสดง

```text
Rule hits 5m / 1h / 24h
Blocked / challenged / scored
Top applications
Top routes and parameters
False-positive decisions
Latency p50 / p95 / p99
Deployment stage
Rule version
Last changed by
Rollback target
```
