"""新模型网关连通性测试 — 验证百度 agent-awd 网关的三个协议端点。"""
import json
import urllib.request
import urllib.error

BASE = "https://agent-awd.baidu.com"
KEY = "4g9NzmKY1Ky3hheJC43c1136C412427a89658f5bB2Fd5e36"
MODEL = "glm-5.2-agent-chanllenge"


def post(path, payload, timeout=90):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


print("=" * 56)
print(f"模型网关连通性测试: {MODEL}")
print("=" * 56)

# 1. Anthropic Messages 协议
print("\n[1] Anthropic /v1/messages")
code, body = post("/v1/messages", {
    "model": MODEL,
    "messages": [{"role": "user", "content": "只回复 OK"}],
    "max_tokens": 100,
})
print(f"  HTTP {code}")
if code == 200:
    try:
        d = json.loads(body)
        print(f"  content[0].text = {d.get('content',[{}])[0].get('text','')}")
        print("  [OK] Anthropic 协议联通")
    except Exception as e:
        print(f"  解析失败: {e}; 原始: {body[:300]}")
else:
    print(f"  body: {body[:400]}")

# 2. OpenAI Chat Completions
print("\n[2] OpenAI /v1/chat/completions")
code, body = post("/v1/chat/completions", {
    "model": MODEL,
    "messages": [{"role": "user", "content": "只回复 OK"}],
    "max_tokens": 100,
    "stream": False,
})
print(f"  HTTP {code}")
if code == 200:
    try:
        d = json.loads(body)
        print(f"  choices[0].message.content = {d.get('choices',[{}])[0].get('message',{}).get('content','')}")
        print("  [OK] OpenAI 协议联通")
    except Exception as e:
        print(f"  解析失败: {e}; 原始: {body[:300]}")
else:
    print(f"  body: {body[:400]}")