import re
import json
import time
import ollama
import matplotlib.pyplot as plt


# HTTP 요청 생성
def build_http_text():
    return "GET /tienda1/publico/anadir.jsp?id=2'+OR+'1'='1 HTTP/1.1"


# Few-shot Prompt
PROMPT_TEMPLATE = '''
You are a web security expert.

Classify each HTTP request as "Normal" or "Anomalous".

Example 1:
Request:
GET /index.jsp HTTP/1.1

Output:
{"label":"Normal","reason":"Safe request"}

Example 2:
Request:
GET /search?q=' OR '1'='1 HTTP/1.1

Output:
{"label":"Anomalous","reason":"SQL Injection detected"}

Now classify:

Request:
{http_text}

Output:
'''


# LLM 분류 함수
def classify_with_llm(http_text, model="gemma3:4b"):

    prompt = PROMPT_TEMPLATE.format(http_text=http_text)

    response = ollama.chat(
        model=model,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        options={"temperature": 0}
    )

    text = response["message"]["content"]

    match = re.search(r"\{[^{}]*\}", text)

    if not match:
        return {
            "label": "Unknown",
            "reason": text
        }

    try:
        return json.loads(match.group())

    except:
        return {
            "label": "Unknown",
            "reason": text
        }


# 입력 데이터 그래프 저장
def show_input_graph(http_text):

    features = {
        "Length": len(http_text),
        "Quote": http_text.count("'"),
        "OR": http_text.upper().count("OR"),
        "=": http_text.count("="),
        "/": http_text.count("/")
    }

    plt.figure(figsize=(8, 4))

    plt.bar(features.keys(), features.values())

    plt.title("HTTP Input Graph")

    plt.xlabel("Feature")

    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig("input_graph.png")

    plt.close()


# 결과 그래프 저장
def show_result_graph(result):

    label = result["label"]

    labels = ["Normal", "Anomalous", "Unknown"]

    values = [
        1 if label == "Normal" else 0,
        1 if label == "Anomalous" else 0,
        1 if label == "Unknown" else 0
    ]

    plt.figure(figsize=(6, 4))

    plt.bar(labels, values)

    plt.title("Classification Result")

    plt.ylabel("Detected")

    plt.tight_layout()

    plt.savefig("result_graph.png")

    plt.close()


# md 파일 생성
def create_md_file(http_text, result, elapsed_time):

    md_text = f"""
# UML 분석 결과값 출력

## 실행 파일

`run_calculation.py`

---

# 입력 HTTP 데이터

```http
{http_text}
```

---

# 입력 데이터 그래프

![input](input_graph.png)

---

# Few-shot 예시

## Example 1

```http
GET /index.jsp HTTP/1.1
```

```json
{{"label":"Normal","reason":"Safe request"}}
```

---

## Example 2

```http
GET /search?q=' OR '1'='1 HTTP/1.1
```

```json
{{"label":"Anomalous","reason":"SQL Injection detected"}}
```

---

# 분류 결과

```json
{json.dumps(result, indent=2)}
```

---

# 결과 그래프

![result](result_graph.png)

---

# 실행 시간

```text
time = run_calculation.py
실행 시간 = {round(elapsed_time, 4)}초
```
"""

    with open("result.md", "w", encoding="utf-8") as f:
        f.write(md_text)


# 메인 실행
def run_calculation():

    start = time.time()

    http_text = build_http_text()

    print("입력 데이터:")
    print(http_text)

    result = classify_with_llm(http_text)

    print("\n결과:")
    print(result)

    show_input_graph(http_text)

    show_result_graph(result)

    end = time.time()

    elapsed_time = end - start

    create_md_file(http_text, result, elapsed_time)

    print("\n파일 생성 완료")
    print("result.md")
    print("input_graph.png")
    print("result_graph.png")


run_calculation()