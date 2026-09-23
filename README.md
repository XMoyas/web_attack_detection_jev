# web_attack_detection_jev

用 TypeSafe **JEV** 对 HTTP/应用 **payload** 做 Web 攻击检测。覆盖 XSS、SQL 注入、XXE、命令注入、路径穿越、SSRF、SSTI 等常见类型。

输入是 payload 字符串，输出结构化判定：`allow` / `review` / `block`。

这是**检测器**，只用于识别恶意输入。仓库里的样例是常见 WAF 探测串，不是 exploit。

Python **>= 3.10**。

## TypeSafe JEV

[JEV](https://typesafe.ai) 是 TypeSafe 的 System One 模型：不做开放式生成，而是对一段 `state` 同时问若干结构化问题。三种原语：

- **Choice**：从给定标签里选一类，并返回置信度
- **Noul**：回答是否，返回 0~1 的概率
- **Score**：按有序量表打分，返回加权分数

一次 `system_one` 里可以放多个问题，时延和费用接近只问一题，适合分类、拦截闸门、严重度评估。本仓库用官方 Python SDK [`typesafe-sdk`](https://pypi.org/project/typesafe-sdk/)，密钥走环境变量 `TYPESAFE_API_KEY`。

**速度与成本：** JEV 面向判定，不生成长文本，单次调用通常在数百毫秒量级。多路问题打包进同一次请求，不必为「是否攻击 + 类型 + 严重度」各打一遍大模型。输出是数字和标签，token 开销远小于 Chat 补全。

**和常用 LLM 的区别：** GPT / Claude 一类模型擅长推理和写作，做检测时要靠 prompt 约束 JSON，再自己解析，容易格式漂移，也没有原生的「是否」概率和选项置信度。JEV 把任务收成 Choice / Noul / Score，结果可直接进阈值（本仓库的 `allow` / `review` / `block`）。它不替代通用 LLM：不写解释、不对话、不做代码生成；Web 攻击检测这种低延迟、要校准分数的闸门，更合适。

## TODO
[] 与常规大语言模型效果及速度对比

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
