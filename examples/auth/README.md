# Auth example

This is the foundation example for [Getting Started] with Waffle.

## Usage

```shell
$ go run main.go
```

## Prevent SQL injection

The `/login` endpoint has a SQL injection vulnerability, though Waffle will block any SQL execution attempts.

```shell
$ curl -X POST 'http://localhost:8080/login' \
    --data "email=user@example.com' OR 1=1--&password=password"
request blocked
```

## Other attack detections

Requests containing requests or attack payloads from penetration testing tools will be detected.

```shell
$ curl 'http://localhost:8080/q?=<script>alert(1)</script>'
...

# Waffle's exporter log output:
2025/10/31 15:26:01 logger.go:41: "msg"="" "error"="detected xss payload: XSS detected" "detected_at"="2025-10-31 15:26:01.170215 +0900 JST m=+346.052140251" "request_url"="http://localhost:8080/q?=<script>alert(1)</script>" "rule_id"="xss-attempts" "block"=false "meta"={}
```
