[기본 프롬포트]


FEWSHOT_PROMPT_TEMPLATE = (
    "You are a web security expert. "
    "Classify each HTTP request as 'Normal' or 'Anomalous'. "
    "For anomalous requests, always provide the attack type and a brief reason.\n\n"
    "Examples:\n"
    "Request: GET /index.jsp HTTP/1.1\n"
    'Output: {{"label": "Normal", "reason": "Standard page request, no suspicious pattern"}}\n\n'
    "Request: POST /login HTTP/1.1\nBody: username=admin&password=12345\n"
    'Output: {{"label": "Normal", "reason": "Typical login request with no suspicious pattern"}}\n\n'
    "Request: GET /search?q=' OR '1'='1 HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "SQL Injection attempt with OR 1=1 pattern"}}\n\n'
    "Request: GET /page?name=<script>alert(1)</script> HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "Reflected XSS attempt using script tags"}}\n\n'
    "Request: GET /admin/../../etc/passwd HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "Path Traversal attempt targeting sensitive file"}}\n\n'
    "Request: POST /submit HTTP/1.1\nBody: command=rm -rf /\n"
    'Output: {{"label": "Anomalous", "reason": "Command Injection attempt in POST body"}}\n\n'
    "Now classify the following request:\n"
    "Request: {http_text}\n"
    "Output:"
)
실행 결과
10/100건 완료 (8.0초, 건당 0.80초)
20/100건 완료 (14.1초, 건당 0.70초)
30/100건 완료 (20.9초, 건당 0.69초)
40/100건 완료 (28.5초, 건당 0.71초)
50/100건 완료 (36.4초, 건당 0.72초)
60/100건 완료 (44.6초, 건당 0.74초)
70/100건 완료 (50.8초, 건당 0.72초)
80/100건 완료 (58.8초, 건당 0.73초)
90/100건 완료 (66.1초, 건당 0.73초)
100/100건 완료 (72.8초, 건당 0.72초)
성능 결과
총 소요: 72.8초
1만 건 환산: 약 121분

LLM 정확도: 0.8400
LLM F1:    0.8294
분류 실패(Unknown): 1건
Classification Report
              precision    recall  f1-score   support

      Normal       0.91      0.80      0.85        56
   Anomalous       0.77      0.90      0.83        44

    accuracy                           0.84       100
   macro avg       0.84      0.85      0.84       100
weighted avg       0.85      0.84      0.84       100
[ollama 프롬포트]
PROMPT_TEMPLATE = (
    "You are a highly experienced web application security analyst.\n"
    "Your task is to classify HTTP requests as either 'Normal' or 'Anomalous'.\n"
    "For anomalous requests, always specify the attack type (e.g., SQL Injection, XSS, Command Injection) and reason.\n\n"
    "Examples:\n"
    "Request: GET /index.jsp HTTP/1.1\n"
    'Output: {{"label": "Normal", "reason": "Standard page request, no suspicious pattern"}}\n\n'
    "Request: GET /search?q=' OR '1'='1 HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "SQL Injection attempt using OR 1=1 pattern"}}\n\n'
    "Now classify the following request:\n"
    "Request: {http_text}\n"
    "Output:"
)
실행 결과
10/100건 완료 (8.2초, 건당 0.82초)
20/100건 완료 (15.0초, 건당 0.75초)
30/100건 완료 (22.9초, 건당 0.76초)
40/100건 완료 (33.1초, 건당 0.83초)
50/100건 완료 (42.9초, 건당 0.86초)
60/100건 완료 (52.1초, 건당 0.87초)
70/100건 완료 (59.9초, 건당 0.85초)
80/100건 완료 (69.2초, 건당 0.86초)
90/100건 완료 (76.8초, 건당 0.85초)
100/100건 완료 (84.2초, 건당 0.84초)
성능 결과
총 소요: 84.2초
1만 건 환산: 약 140분

LLM 정확도: 0.6900
LLM F1:    0.7261
분류 실패(Unknown): 1건
Classification Report
              precision    recall  f1-score   support

      Normal       0.91      0.50      0.65        56
   Anomalous       0.60      0.93      0.73        44

    accuracy                           0.69       100
   macro avg       0.75      0.72      0.69       100
weighted avg       0.77      0.69      0.68       100
[Few-shot 프롬포트]
FEWSHOT_PROMPT_TEMPLATE = (
    "You are a web security expert. "
    "Classify each HTTP request as 'Normal' or 'Anomalous'. "
    "For anomalous requests, always provide the attack type and a brief reason.\n\n"
    "Examples:\n"
    "Request: GET /index.jsp HTTP/1.1\n"
    'Output: {{"label": "Normal", "reason": "Standard page request, no suspicious pattern"}}\n\n'
    "Request: POST /login HTTP/1.1\nBody: username=admin&password=12345\n"
    'Output: {{"label": "Normal", "reason": "Typical login request with no suspicious pattern"}}\n\n'
    "Request: GET /search?q=' OR '1'='1 HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "SQL Injection attempt with OR 1=1 pattern"}}\n\n'
    "Request: GET /page?name=<script>alert(1)</script> HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "Reflected XSS attempt using script tags"}}\n\n'
    "Request: GET /admin/../../etc/passwd HTTP/1.1\n"
    'Output: {{"label": "Anomalous", "reason": "Path Traversal attempt targeting sensitive file"}}\n\n'
    "Request: POST /submit HTTP/1.1\nBody: command=rm -rf /\n"
    'Output: {{"label": "Anomalous", "reason": "Command Injection attempt in POST body"}}\n\n'
    "Now classify the following request:\n"
    "Request: {http_text}\n"
    "Output:"
)
실행 결과
10/100건 완료 (7.1초, 건당 0.71초)
20/100건 완료 (13.4초, 건당 0.67초)
30/100건 완료 (20.5초, 건당 0.68초)
40/100건 완료 (28.2초, 건당 0.70초)
50/100건 완료 (35.9초, 건당 0.72초)
60/100건 완료 (43.2초, 건당 0.72초)
70/100건 완료 (50.0초, 건당 0.71초)
80/100건 완료 (58.1초, 건당 0.72초)
90/100건 완료 (65.2초, 건당 0.72초)
100/100건 완료 (72.0초, 건당 0.72초)
성능 결과
총 소요: 72.0초
1만 건 환산: 약 120분

LLM 정확도: 0.7400
LLM F1:    0.7598
분류 실패(Unknown): 1건
Classification Report
              precision    recall  f1-score   support

      Normal       0.92      0.59      0.72        56
   Anomalous       0.64      0.93      0.76        44

    accuracy                           0.74       100
   macro avg       0.78      0.76      0.74       100
weighted avg       0.80      0.74      0.74       100ㄴ
