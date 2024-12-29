# Example of preventing SQL injection with Waffle

This example demonstrates how to prevent SQL injection using Waffle.

## Usage

```shell
$ go run main.go
```

## Prevent SQL injection

```shell
$ curl -X POST 'http://localhost:8000/insecure-login' \
    --data "email=user@example.com&password=password"
{"message":"success"}
```

```shell
$ curl -X POST 'http://localhost:8000/insecure-login' \
    --data "email=user@example.com' OR 1=1--&password=password"
{"error":"blocked by rule exploit-sql-injection with inspector sqli"}
```
