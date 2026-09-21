# web_attack_detection_jev

用 TypeSafe **JEV** 对 HTTP/应用 **payload** 做 Web 攻击检测。覆盖 XSS、SQL 注入、XXE、命令注入、路径穿越、SSRF、SSTI 等常见类型。

输入是 payload 字符串，输出结构化判定：`allow` / `review` / `block`。

这是**检测器**，只用于识别恶意输入。仓库里的样例是常见 WAF 探测串，不是 exploit。

Python **>= 3.10**。

## 架构

```text
payload (+ 可选 content_type / path)
        │
        ▼
  WebAttackDetector
        │  一次 system_one 调用
        ▼
  JEV: Noul / Choice / Score
        │
        ▼
  阈值决策  →  allow | review | block
```

| 字段 | JEV 原语 | 含义 |
| --- | --- | --- |
| `is_attack` | Noul | 是攻击的概率 0~1 |
| `attack_type` | Choice | xss / sql_injection / xxe / ... / benign |
| `severity` | Score | 0 无害 ~ 3 高危 |
| `should_block` | Noul | 是否应该拦截 |

阈值在 `config.py`：攻击 0.65、拦截 0.70、复核 0.40。空 payload 不调模型，直接 `allow`。

## 准备

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # 填入 TYPESAFE_API_KEY
```

国内镜像若 SSL 失败，改用官方源：

```bash
pip install -i https://pypi.org/simple -r requirements.txt
```

密钥只放在本地 `.env`，不要提交到 Git。

## 用法

单条检测：

```bash
python cli.py detect "<script>alert(1)</script>"
python cli.py detect --file payload.txt --content-type application/xml --path /upload
```

内置样例（会调用 JEV，消耗配额）：

```bash
python cli.py demo
```

HTTP 服务：

```bash
python cli.py serve --port 8000
```

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/detect \
  -H 'Content-Type: application/json' \
  -d '{"payload":"<script>alert(1)</script>","path":"/comment"}'
```

文档：http://127.0.0.1:8000/docs

返回示例：

```json
{
  "payload": "<script>alert(1)</script>",
  "is_attack": true,
  "attack_type": "xss",
  "attack_probability": 0.98,
  "attack_confidence": 1.0,
  "severity": 1.91,
  "should_block": 0.93,
  "action": "block",
  "truncated": false,
  "path": "/comment"
}
```

`action=block` 时 CLI 退出码为 1，方便脚本接入。

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

单测 mock 了 JEV，不消耗配额。`demo` 和 HTTP `/detect` 会打真实接口。

样例数据在 [`data/samples.json`](data/samples.json)。

## License

MIT
