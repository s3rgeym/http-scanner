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

Example Usage:

```bash
$ echo 'example.com' | http-scanner -p '/{archive,site,backup}.{zip,tar.{g,x}z}' -nct 'text/html' -nr '(?i)<html' -cl '>0' -S dumps -a -l debug
INFO[2024-09-23T15:31:08+03:00] Scanning started!
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/site.zip
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/archive.tar.gz
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/backup.tar.xz
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/site.tar.gz
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/site.tar.xz
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/backup.zip
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/backup.zip: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/backup.tar.gz
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/archive.zip
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/archive.zip: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/site.zip: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/backup.tar.gz: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/site.tar.gz: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/site.tar.xz: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/backup.tar.xz: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/archive.tar.gz: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.0.0 Safari/537.36
DEBU[2024-09-23T15:31:08+03:00] Probing URL: https://example.com/archive.tar.xz
DEBU[2024-09-23T15:31:08+03:00] User-Agent for https://example.com/archive.tar.xz: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
WARN[2024-09-23T15:31:08+03:00] URL https://example.com/site.zip body matches not-allowed regex (?i)<html
{"input":"example.com","url":"https://example.com/backup.tar.gz","method":"GET","host":"example.com","path":"/backup.tar.gz","completion_date":"2024-09-23T15:31:08+03:00","status":200,"content_type":"application/octet-stream","content_length":1517,"ip":"120.34.56.78"}
INFO[2024-09-23T15:31:08+03:00] File saved: dumps/example.com/backup.tar.gz
WARN[2024-09-23T15:31:08+03:00] Bad status for URL https://example.com/site.tar.gz: 404
WARN[2024-09-23T15:31:08+03:00] Bad status for URL https://example.com/archive.tar.gz: 404
WARN[2024-09-23T15:31:08+03:00] Bad status for URL https://example.com/archive.zip: 404
WARN[2024-09-23T15:31:08+03:00] Bad status for URL https://example.com/backup.zip: 404
WARN[2024-09-23T15:31:09+03:00] Bad status for URL https://example.com/site.tar.xz: 404
WARN[2024-09-23T15:31:09+03:00] Bad status for URL https://example.com/backup.tar.xz: 404
WARN[2024-09-23T15:31:09+03:00] Bad status for URL https://example.com/archive.tar.xz: 404
INFO[2024-09-23T15:31:09+03:00] Scanning finished!
```

- `-p '/{archive,site,backup}.{zip,tar.{g,x}z}'`: Specifies the path for bash expansion, expanding to paths like `/archive.zip`, `/site.zip`, `/backup.zip`, `/archive.tar.gz`, `/site.tar.gz`, `/backup.tar.gz`, `/archive.tar.xz`, `/site.tar.xz`, `/backup.tar.xz`.

- `-nct 'text/html'`: Filters out responses with the content type `text/html`, ignoring responses that have `Content-Type: text/html`.

- `-nr '(?i)<html'`: Filters out responses whose body matches the regex `(?i)<html`, ignoring responses that contain `<html` in their body, case-insensitive.

- `-cl '>0'`: Filters responses based on content length, only including responses with a content length greater than 0.

- `-S dumps`: Specifies the directory to save files to, saving files to the `dumps` directory.

- `-a`: Archives and deletes the save directory after completion, creating a ZIP archive of the `dumps` directory and deleting the directory.

- `-l debug`: Sets the log level to debug, enabling detailed logging for debugging purposes.

See help:

```bash
http-scanner -h
```
