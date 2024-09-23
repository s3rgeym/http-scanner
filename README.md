# HTTP Scanner

HTTP Scanner is a command-line tool written in Go that allows you to scan HTTP URLs using bash-style path patterns. The tool supports brace expansion, regex filtering, and other useful features.

## Features

- **Path Pattern Expansion**: Supports bash-style path pattern expansion using curly braces.
- **Regex Filtering**: Ability to filter responses using regular expressions.
- **Parallel Scanning**: Uses multiple goroutines for parallel URL scanning.
- **Logging Levels**: Supports various logging levels (debug, info, warning, error).
- **JSON Output**: Ability to output scan results in JSON format.
- ...

## Installation

```bash
go get github.com/s3rgeym/http-scanner
```

## Usage

```bash
echo 'example.com' | http-scanner -p '/{archive,site,backup}.{zip,tar.{x,g}z}' -nct 'text/html' -nr '<html' -l debug -S backups

http-scanner -h
```
