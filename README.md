# HTTP Scanner 🔍

HTTP Scanner is a command-line tool written in Go that allows you to search for specific paths on servers by checking their content using regular expressions. This tool is particularly useful for finding vulnerabilities, sensitive information, and other data of interest on web servers.

## Installation 📦

```bash
go install github.com/s3rgeym/http-scanner
```

Ready-to-use builds for Linux, Mac OS, and Windows can be downloaded from the [releases page](../../releases).

## Usage 🚀

Example Usage:

```bash
echo 'example.com' | http-scanner -nct 'text/html' -nr '(?i)<html' -cl '>0' -S dumps -a -l debug /{archive,site,backup}.{zip,tar.{g,x}z}
```

- `echo 'example.com' |`: Passes the string example.com to the standard input of the http-scanner utility.

- `-nct 'text/html'`: Filters out responses with the content type `text/html`, ignoring responses that have `Content-Type: text/html`.

- `-nr '(?i)<html'`: Filters out responses whose body matches the regex `(?i)<html`, ignoring responses that contain `<html` in their body, case-insensitive.

- `-cl '>0'`: Filters responses based on content length, only including responses with a content length greater than 0.

- `-S dumps`: Specifies the directory to save files to, saving files to the `dumps` directory.

- `-a`: Archives and deletes the save directory after completion, creating a ZIP archive of the `dumps` directory and deleting the directory.

- `-l debug`: Sets the log level to debug, enabling detailed logging for debugging purposes.

- `/{archive,site,backup}.{zip,tar.{g,x}z}`: this expression will be transformed by the shell into a list of paths to check.

The results are output in JSONL format, where each JSON document is placed on a new line.

Example of JSONL Output:

```json
{"input":"example.com","url":"https://example.com/backup.tar.gz","method":"GET","host":"example.com","path":"/backup.tar.gz","completion_date":"2024-09-23T15:31:08+03:00","status":200,"content_type":"application/octet-stream","content_length":1517,"ip":"120.34.56.78"}
```

See help:

```bash
http-scanner -h
```
