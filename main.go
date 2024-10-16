package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/yeka/zip"
	"golang.org/x/net/idna"
	"golang.org/x/time/rate"
)

type Result struct {
	Input          string `json:"input"`
	URL            string `json:"url"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	CompletionDate string `json:"completion_date"`
	Status         int    `json:"status"`
	ContentType    string `json:"content_type"`
	ContentLength  int64  `json:"content_length"`
	IP             string `json:"ip"`
}

type CheckPath struct {
	Url  string
	Path string
}

var log = logrus.New()

func main() {
	inputFile := flag.String("i", "-", "Input file with URLs")
	outputFile := flag.String("o", "-", "Output file for JSON results")
	logLevel := flag.String("l", "warning", "Log level (error, warning, info, debug)")
	regex := flag.String("r", "", "Regex to check response body")
	notRegex := flag.String("nr", "", "Regex that body should not match")
	contentLengthFilter := flag.String("cl", "", "Filter for content length (e.g. '100', '100-200', '< 100', '<= 100', '> 100', '>= 100')")
	contentType := flag.String("ct", "", "Expected content type (main type and subtype only)")
	notContentType := flag.String("nct", "", "Content type that body should not match")
	statusCodes := flag.String("sc", "200", "Filter for status codes (e.g. '200', '200-299,400,401,403,404', '200-599')")
	workers := flag.Int("w", 20, "Number of parallel workers")
	followRedirects := flag.Bool("F", false, "Follow redirects")
	forceHTTPS := flag.Bool("https", false, "Force HTTPS")
	connectionTimeout := flag.Duration("connection-timeout", 10*time.Second, "Timeout for establishing a connection")
	readHeaderTimeout := flag.Duration("read-header-timeout", 5*time.Second, "Timeout for reading response headers")
	totalTimeout := flag.Duration("t", 90*time.Second, "Total timeout for the entire request")
	saveDirectory := flag.String("S", "", "Save files to directory")
	archive := flag.Bool("a", false, "Archive and delete the save directory after completion")
	maxRetries := flag.Int("retries", 1, "Number of retry attempts")
	rps := flag.Int("rps", 150, "Maximum number of requests per second")
	proxyURL := flag.String("proxy", "", "Proxy URL (e.g., http://example.com:8080 or socks5://localhost:1080)")
	maxHostErrors := flag.Int("maxhe", 30, "Maximum number of errors per host before ignoring further requests")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s [ flags ] path [ path ... ]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	paths := flag.Args()

	if len(paths) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.SetOutput(colorable.NewColorableStderr())
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:    true,
		FullTimestamp:  true,
		DisableSorting: true,
	})
	setLogLevel(*logLevel)

	urls, err := readURLs(*inputFile, *forceHTTPS)
	if err != nil {
		log.Fatalf("Error reading URLs: %v", err)
	}

	allowedStatuses, err := parseStatusCodes(*statusCodes)
	if err != nil {
		log.Fatalf("Error parsing status codes: %v", err)
	}

	contentLengthFilterFunc, err := parseContentLengthFilter(*contentLengthFilter)
	if err != nil {
		log.Fatalf("Error parsing content length filter: %v", err)
	}

	writer := createWriter(*outputFile)
	defer writer.Flush()

	limiter := rate.NewLimiter(rate.Limit(*rps), *rps)
	client := configureHTTPClient(*proxyURL, *connectionTimeout, *readHeaderTimeout, *maxRetries, *followRedirects, limiter)

	var wg sync.WaitGroup
	checkPaths := make(chan CheckPath)
	hostErrors := make(map[string]int)
	var mut sync.Mutex
	seen := sync.Map{}

	log.Debug("Scanning started.")

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			log.Debugf("Worker #%d started.", id)

			for checkPath := range checkPaths {
				func() {
					url := checkPath.Url
					host := getHostWithoutPort(url)

					if shouldSkipHost(host, hostErrors, &mut, *maxHostErrors) {
						return
					}

					fullURL, err := urlJoin(url, checkPath.Path)
					if err != nil {
						log.Errorf("Error: %v", err)
						return
					}

					if _, visited := seen.Load(fullURL); visited {
						log.Warnf("URL %s has already been visited, skipping", fullURL)
						return
					}
					seen.Store(fullURL, true)

					log.Debugf("Probing URL: %s", fullURL)

					req, err := retryablehttp.NewRequest("GET", fullURL, nil)
					if err != nil {
						log.Errorf("Error creating request for URL %s: %v", fullURL, err)
						return
					}

					setRequestHeaders(req)

					log.Debugf("User-Agent for URL %s: %s", req.URL, req.Header.Get("User-Agent"))

					ctx, cancel := context.WithTimeout(req.Context(), *totalTimeout) // Максимальное время на выполнение запроса
					defer cancel()

					req = req.WithContext(ctx)

					resp, err := client.Do(req)
					if err != nil {
						log.Warnf("Error probing URL %s: %v", fullURL, err)
						incrementHostError(host, hostErrors, &mut)
						return
					}
					defer resp.Body.Close()

					if !isStatusAllowed(resp.StatusCode, allowedStatuses) {
						log.Warnf("Bad status for URL %s: %d", fullURL, resp.StatusCode)
						return
					}

					if !contentLengthFilterFunc(resp.ContentLength) {
						log.Warnf("Content length %d for URL %s does not match the filter.", resp.ContentLength, fullURL)
						return
					}

					mimeType := parseMimeType(resp.Header.Get("Content-Type"))

					if *contentType != "" && *contentType != mimeType {
						log.Warnf("URL %s returned content type %s, expected %s", fullURL, mimeType, *contentType)
						return
					}

					if *notContentType != "" && *notContentType == mimeType {
						log.Warnf("URL %s returned content type %s, which should not match %s", fullURL, mimeType, *notContentType)
						return
					}

					body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
					if err != nil {
						log.Errorf("Error reading response body for URL %s: %v", fullURL, err)
						return
					}

					if *regex != "" {
						if !matchRegex(string(body), *regex) {
							log.Warnf("URL %s body does not match regex %s", fullURL, *regex)
							return
						}
					}

					if *notRegex != "" {
						if matchRegex(string(body), *notRegex) {
							log.Warnf("URL %s body matches not-allowed regex %s", fullURL, *notRegex)
							return
						}
					}

					if *saveDirectory != "" {
						saveFile(body, resp, *saveDirectory)
					}

					completionDate := time.Now().Format(time.RFC3339)
					ip := getIP(resp)
					result := Result{
						Input:          checkPath.Url,
						URL:            resp.Request.URL.String(),
						Method:         req.Method,
						Host:           resp.Request.URL.Host,
						Path:           resp.Request.URL.Path,
						CompletionDate: completionDate,
						Status:         resp.StatusCode,
						ContentType:    mimeType,
						ContentLength:  resp.ContentLength,
						IP:             ip,
					}

					outputResult(writer, result, &mut)
				}()
			}

			log.Debugf("Worker #%d finished!", id)
		}(i)
	}

	for _, url := range urls {
		for _, path := range paths {
			checkPaths <- CheckPath{Url: url, Path: path}
		}
	}

	close(checkPaths)

	wg.Wait()

	if *archive && *saveDirectory != "" {
		archiveAndDelete(*saveDirectory)
	}

	log.Debug("Scanning finished!")
}

func shouldSkipHost(host string, hostErrors map[string]int, mut *sync.Mutex, maxHostErrors int) bool {
	mut.Lock()
	defer mut.Unlock()
	if hostErrors[host] >= maxHostErrors {
		log.Warnf("Host %s has exceeded the maximum number of errors, skipping further requests", host)
		return true
	}
	return false
}

func incrementHostError(host string, hostErrors map[string]int, mut *sync.Mutex) {
	mut.Lock()
	hostErrors[host]++
	mut.Unlock()
}

func setRequestHeaders(req *retryablehttp.Request) {
	headers := map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"Referer":         "https://www.google.com/",
		"User-Agent":      randomChromeUserAgent(),
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func readURLs(filename string, forceHTTPS bool) ([]string, error) {
	var input *os.File = os.Stdin
	if filename != "-" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		input = file
	}
	var urls []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		url := scanner.Text()
		normalizedURL, err := normalizeURL(url, forceHTTPS)
		if err != nil {
			log.Warnf("Error normalizing URL %s: %v", url, err)
			continue
		}
		urls = append(urls, normalizedURL)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func setLogLevel(logLevel string) {
	logLevel = strings.ToLower(logLevel)
	switch {
	case strings.HasPrefix("error", logLevel):
		log.SetLevel(logrus.ErrorLevel)
	case strings.HasPrefix("warning", logLevel):
		log.SetLevel(logrus.WarnLevel)
	case strings.HasPrefix("info", logLevel):
		log.SetLevel(logrus.InfoLevel)
	case strings.HasPrefix("debug", logLevel):
		log.SetLevel(logrus.DebugLevel)
	default:
		log.SetLevel(logrus.WarnLevel)
	}
}

func parseMimeType(contentType string) string {
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return ""
	}

	mimeParts := strings.Split(strings.TrimSpace(parts[0]), "/")
	if len(mimeParts) != 2 {
		return ""
	}

	mainType := strings.TrimSpace(mimeParts[0])
	subType := strings.TrimSpace(mimeParts[1])

	return strings.ToLower(mainType + "/" + subType)
}

func randomIntInRange(a, b int) int {
	return a + rand.Intn(b-a+1)
}

func randomChromeUserAgent() string {
	platforms := []string{
		"Windows NT 10.0; Win64; x64",
		"Macintosh; Intel Mac OS X 10_15_7",
		"X11; Linux x86_64",
	}
	return fmt.Sprintf(
		"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		platforms[rand.Int()%len(platforms)],
		randomIntInRange(80, 129),
	)
}

func getIP(resp *http.Response) string {
	host, _, err := net.SplitHostPort(resp.Request.URL.Host)
	if err != nil {
		host = resp.Request.URL.Host
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func createWriter(filename string) *bufio.Writer {
	if filename != "-" {
		file, err := os.Create(filename)
		if err != nil {
			log.Errorf("Error creating output file: %v", err)
		}
		return bufio.NewWriter(file)
	}
	return bufio.NewWriter(os.Stdout)
}

func urlJoin(baseURL string, paths ...string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("error parsing base URL: %w", err)
	}
	for _, path := range paths {
		additional, err := url.Parse(path)
		if err != nil {
			return "", fmt.Errorf("error parsing additional path: %w", err)
		}
		base = base.ResolveReference(additional)
	}

	return base.String(), nil
}

func saveFile(initialBody []byte, resp *http.Response, saveDirectory string) {
	u := resp.Request.URL

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	path := u.Path

	savePath := filepath.Join(saveDirectory, host, path)
	savePath = strings.TrimSuffix(savePath, "/")

	err = os.MkdirAll(filepath.Dir(savePath), 0755)
	if err != nil {
		log.Errorf("Error creating directory %s: %v", filepath.Dir(savePath), err)
		return
	}

	file, err := os.Create(savePath)
	if err != nil {
		log.Errorf("Error creating file %s: %v", savePath, err)
		return
	}
	defer file.Close()

	// Write the initial body to the file
	_, err = file.Write(initialBody)
	if err != nil {
		log.Errorf("Error writing to file %s: %v", savePath, err)
		return
	}

	// Copy the remaining data from the response body to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		log.Errorf("Error writing to file %s: %v", savePath, err)
		return
	}

	log.Infof("File saved: %s", savePath)
}

func parseStatusCodes(input string) ([][2]int, error) {
	var ranges [][2]int

	if input == "" {
		return ranges, nil
	}

	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			min, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid lower bound: %s", bounds[0])
			}
			max, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid upper bound: %s", bounds[1])
			}
			if min > max {
				return nil, fmt.Errorf("lower bound greater than upper bound: %s", part)
			}
			ranges = append(ranges, [2]int{min, max})
		} else {
			value, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid status code: %s", part)
			}
			ranges = append(ranges, [2]int{value, value})
		}
	}
	return ranges, nil
}

func isStatusAllowed(status int, ranges [][2]int) bool {
	if len(ranges) == 0 {
		return true // Если диапазоны пустые, нет фильтрации
	}
	for _, r := range ranges {
		if status >= r[0] && status <= r[1] {
			return true
		}
	}
	return false
}

func configureHTTPClient(proxyURL string, connectionTimeout time.Duration, readHeaderTimeout time.Duration, maxRetries int, followRedirects bool, limiter *rate.Limiter) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.RetryMax = maxRetries
	client.HTTPClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(nil),
			DialContext: (&net.Dialer{
				Timeout: connectionTimeout, // Таймаут на установление соединения
			}).DialContext,
			ResponseHeaderTimeout: readHeaderTimeout, // Таймаут на получение заголовков
		},
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			logrus.Fatalf("Failed to parse proxy URL: %v", err)
		}
		client.HTTPClient.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	}

	client.RequestLogHook = func(logger retryablehttp.Logger, req *http.Request, retry int) {
		limiter.Wait(req.Context())
	}

	// Отключаем отладочный вывод в retryablehttp
	client.Logger = nil

	return client
}

func archiveAndDelete(saveDirectory string) {
	// Проверка существования каталога
	if _, err := os.Stat(saveDirectory); os.IsNotExist(err) {
		log.Warnf("Save directory %s does not exist, skipping archiving and deletion", saveDirectory)
		return
	}

	archivePath := strings.TrimRight(saveDirectory, "/") + ".zip"

	// Create a new ZIP archive with the specified passphrase
	file, err := os.Create(archivePath)
	if err != nil {
		log.Fatalf("Failed to create archive file: %v", err)
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	err = filepath.Walk(saveDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		relPath, err := filepath.Rel(saveDirectory, path)
		if err != nil {
			return err
		}

		zipFile, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(zipFile, file)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Failed to archive directory: %v", err)
	}

	err = os.RemoveAll(saveDirectory)
	if err != nil {
		log.Fatalf("Failed to delete directory: %v", err)
	}

	log.Infof("Directory archived and deleted: %s", archivePath)
}

func parseContentLengthFilter(filter string) (func(int64) bool, error) {
	filter = strings.TrimSpace(filter)

	if filter == "" {
		return func(int64) bool { return true }, nil
	}

	switch {
	case strings.HasPrefix(filter, "<="):
		value, err := strconv.ParseInt(strings.TrimSpace(filter[2:]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		return func(contentLength int64) bool {
			return contentLength <= value
		}, nil
	case strings.HasPrefix(filter, ">="):
		value, err := strconv.ParseInt(strings.TrimSpace(filter[2:]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		return func(contentLength int64) bool {
			return contentLength >= value
		}, nil
	case strings.HasPrefix(filter, "<"):
		value, err := strconv.ParseInt(strings.TrimSpace(filter[1:]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		return func(contentLength int64) bool {
			return contentLength < value
		}, nil
	case strings.HasPrefix(filter, ">"):
		value, err := strconv.ParseInt(strings.TrimSpace(filter[1:]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		return func(contentLength int64) bool {
			return contentLength > value
		}, nil
	case strings.Contains(filter, "-"):
		parts := strings.Split(filter, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		min, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		max, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content length filter: %s", filter)
		}
		return func(contentLength int64) bool {
			return contentLength >= min && contentLength <= max
		}, nil
	}

	length, err := strconv.ParseInt(filter, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid content length filter: %s", filter)
	}
	return func(contentLength int64) bool {
		return contentLength == length
	}, nil
}

func getHostWithoutPort(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		return ""
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host
	}
	return host
}

func matchRegex(body, regex string) bool {
	matched, err := regexp.MatchString(regex, body)
	if err != nil {
		return false
	}
	return matched
}

func outputResult(writer *bufio.Writer, result Result, mut *sync.Mutex) {
	data, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Error marshaling result: %v", err)
		return
	}
	mut.Lock()
	fmt.Fprintln(writer, string(data))
	writer.Flush()
	mut.Unlock()
}

func normalizeURL(urlString string, forceHTTPS bool) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	if forceHTTPS && u.Scheme == "http" {
		u.Scheme = "https"
	}

	if u.Host != "" {
		punycodeHost, err := idna.ToASCII(u.Host)
		if err != nil {
			return "", err
		}
		u.Host = punycodeHost
	}

	return u.String(), nil
}
