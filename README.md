# HTTP Scanner 🔍

HTTP Scanner is a command-line tool written in Go that allows you to scan HTTP URLs using bash-style path patterns. The tool supports brace expansion, regex filtering, and other useful features.

## Features 🌟

- **Path Pattern Expansion**: Supports bash-style path pattern expansion using curly braces.
- **Regex Filtering**: Ability to filter responses using regular expressions.
- **Parallel Scanning**: Uses multiple goroutines for parallel URL scanning.
- **Logging Levels**: Supports various logging levels (debug, info, warning, error).
- **JSON Output**: Ability to output scan results in JSON format.
- **File Saving**: Optionally saves found files to a specified directory, preserving the directory structure from the server.

## Installation 📦

```bash
go get github.com/s3rgeym/http-scanner
```

## Usage 🚀

```bash
http-scanner -h
```

Example:

```bash
$ echo 'example.com' | http-scanner -p '/{archive,site,backup}.{zip,tar.{g,x}z}' -nct 'text/html' -nr '(?i)<html' -l debug -S dumps
INFO[2024-09-23T13:59:10+03:00] Scanning started!
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/site.zip
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/archive.tar.gz
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/site.tar.xz
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/backup.zip
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/backup.zip: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/site.tar.gz
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/site.tar.gz: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/site.tar.xz: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/site.zip: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/archive.tar.gz: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/archive.tar.xz
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/archive.tar.xz: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/archive.zip
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/archive.zip: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/backup.tar.gz
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/backup.tar.gz: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.0.0 Safari/537.36
DEBU[2024-09-23T13:59:10+03:00] Probing URL: https://example.com/backup.tar.xz
DEBU[2024-09-23T13:59:10+03:00] User-Agent for https://example.com/backup.tar.xz: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
WARN[2024-09-23T13:59:10+03:00] URL https://example.com/site.zip body matches not-allowed regex <html
{"input":"example.com","url":"https://example.com/backup.tar.gz","method":"GET","host":"example.com","path":"/backup.tar.gz","completion_date":"2024-09-23T13:59:10+03:00","status":200,"content_type":"application/octet-stream","content_length":1517,"ip":"12.34.56.78"}
INFO[2024-09-23T13:59:10+03:00] File saved: dumps/example.com/backup.tar.gz
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/archive.zip is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/archive.tar.xz is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/archive.tar.gz is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/site.tar.gz is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/backup.tar.xz is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/site.tar.xz is not in allowed range.
WARN[2024-09-23T15:24:58+03:00] Status 404 for URL https://example.com/backup.zip is not in allowed range.
INFO[2024-09-23T13:59:11+03:00] Scanning finished!
```
