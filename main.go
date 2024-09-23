package main

import (
	"bufio"
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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	// go mod init <project-name>
	// go get <dependecy>
	// go mod edit -droprequire=<dependency>
	// go mod tidy
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
)

type Result struct {
	Input          string `json:"input"`           // Входной URL
	URL            string `json:"url"`             // Конечный URL (после редиректов)
	Method         string `json:"method"`          // Метод запроса
	Host           string `json:"host"`            // Хост
	Path           string `json:"path"`            // Путь с query string
	CompletionDate string `json:"completion_date"` // Дата завершения запроса
	Status         int    `json:"status"`          // Статус ответа
	ContentType    string `json:"content_type"`    // Content-Type ответа
	ContentLength  int64  `json:"content_length"`  // Длина контента
	IP             string `json:"ip"`              // IP-адрес
}

var log = logrus.New()

func main() {
	inputFile := flag.String("i", "", "Input file with URLs")
	outputFile := flag.String("o", "", "Output file for JSON results")
	logLevel := flag.String("l", "warning", "Log level (error, warning, info, debug)")
	path := flag.String("p", "", "Path for bash expansion")
	regex := flag.String("r", "", "Regex to check response body")
	notRegex := flag.String("nr", "", "Regex that body should not match")
	contentType := flag.String("ct", "", "Expected content type (main type and subtype only)")
	notContentType := flag.String("nct", "", "Content type that body should not match")
	statusCodes := flag.String("sc", "200", "Filter for status codes (e.g. '200', '200-299,400,401,403,404', '200-599')")
	workers := flag.Int("w", 20, "Number of parallel workers")
	followRedirects := flag.Bool("F", false, "Follow redirects")
	forceHTTPS := flag.Bool("https", false, "Force HTTPS")
	timeout := flag.Duration("t", 15*time.Second, "HTTP request timeout")
	saveDirectory := flag.String("S", "", "Save files to directory")
	flag.Parse()

	log.SetOutput(colorable.NewColorableStderr())
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:    true,
		FullTimestamp:  true,
		DisableSorting: true,
		// DisableLevelTruncation: true,
	})
	setLogLevel(*logLevel)

	urls, err := readURLs(*inputFile)
	if err != nil {
		log.Fatalf("Error reading URLs: %v", err)
	}

	paths := expandBraces(*path)
	//log.Debugf("Expanded path: %v", paths)

	allowedStatuses, err := parseStatusCodes(*statusCodes)
	if err != nil {
		log.Fatalf("Error parsing status codes: %v", err)
	}

	writer := createWriter(*outputFile)
	defer writer.Flush()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *workers)

	log.Info("Scanning started!")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !*followRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: *timeout,
	}

	for _, url := range urls {
		for _, path := range paths {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(url, path string) {
				defer func() {
					<-semaphore
					wg.Done()
				}()
				fullURL, err := urlJoin(ensureScheme(url, *forceHTTPS), path)
				if err != nil {
					log.Errorf("Error: %v", err)
					return
				}
				log.Debugf("Probing URL: %s", fullURL)
				req, err := http.NewRequest("GET", fullURL, nil)
				if err != nil {
					log.Errorf("Error creating request for URL %s: %v", fullURL, err)
					return
				}

				for key, value := range getDefaultHeaders() {
					req.Header.Set(key, value)
				}

				log.Debugf("User-Agent for %s: %s", fullURL, req.Header.Get("User-Agent"))

				resp, err := client.Do(req)
				if err != nil {
					log.Warnf("Error probing URL %s: %v", fullURL, err)
					return
				}
				defer resp.Body.Close()

				if !isStatusAllowed(resp.StatusCode, allowedStatuses) {
					log.Warnf("Status %d for URL %s is not in allowed range.", resp.StatusCode, fullURL)
					return
				}

				contentTypeHeader := resp.Header.Get("Content-Type")
				mimeType := parseMimeType(contentTypeHeader)

				if *contentType != "" {
					if *contentType != mimeType {
						log.Warnf("URL %s returned content type %s, expected %s", fullURL, mimeType, *contentType)
						return
					}
				}

				if *notContentType != "" {
					if *notContentType == mimeType {
						log.Warnf("URL %s returned content type %s, which should not match %s", fullURL, mimeType, *notContentType)
						return
					}
				}

				body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
				if err != nil {
					log.Errorf("Error reading response body for URL %s: %v", fullURL, err)
					return
				}

				if *regex != "" {
					matched, err := regexp.MatchString(*regex, string(body))
					if err != nil || !matched {
						log.Warnf("URL %s body does not match regex %s", fullURL, *regex)
						return
					}
				}

				if *notRegex != "" {
					matched, err := regexp.MatchString(*notRegex, string(body))
					if err != nil || matched {
						log.Warnf("URL %s body matches not-allowed regex %s", fullURL, *notRegex)
						return
					}
				}

				completionDate := time.Now().Format(time.RFC3339)
				ip := getIP(resp)
				result := Result{
					Input:          url,
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

				// Immediately output result
				data, err := json.Marshal(result)
				if err != nil {
					log.Errorf("Error marshaling result: %v", err)
					return
				}
				fmt.Fprintln(writer, string(data))
				writer.Flush()

				if *saveDirectory != "" {
					saveFile(body, resp, *saveDirectory)
				}
			}(url, path)
		}
	}

	wg.Wait()
	log.Infof("Scanning finished!")
}

func getDefaultHeaders() map[string]string {
	return map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"User-Agent":      randomChromeUserAgent(),
	}
}

func readURLs(filename string) ([]string, error) {
	if filename != "" {
		return readURLsFromFile(filename)
	}
	return readURLsFromStdin()
}

func readURLsFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return splitLines(string(data)), nil
}

func readURLsFromStdin() ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func splitLines(data string) []string {
	var lines []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
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

// https://algo.monster/liteproblems/1096
// expandBraces takes a brace expression and returns all possible expansions.
func expandBraces(expression string) []string {
	// Set to store the expanded results
	expandedSet := map[string]bool{}

	// Helper function to recursively perform DFS on the expression
	var dfs func(string)
	dfs = func(exp string) {
		// Find the first closing brace
		closingBraceIndex := strings.Index(exp, "}")
		if closingBraceIndex == -1 {
			// If no closing brace is found, add the expression to the set
			expandedSet[exp] = true
			return
		}

		// Find the last opening brace before the first closing brace
		openingBraceIndex := strings.LastIndex(exp[:closingBraceIndex], "{")

		// Divide the expression into three parts: before, inside, and after the braces
		beforeBrace := exp[:openingBraceIndex]
		afterBrace := exp[closingBraceIndex+1:]
		insideBraces := exp[openingBraceIndex+1 : closingBraceIndex]

		// Split the inside of the braces by commas and recurse
		options := strings.Split(insideBraces, ",")
		for _, option := range options {
			dfs(beforeBrace + option + afterBrace)
		}
	}

	// Start the recursive DFS
	dfs(expression)

	// Collect the results and sort them
	result := make([]string, 0, len(expandedSet))
	for exp := range expandedSet {
		result = append(result, exp)
	}
	sort.Strings(result)
	return result
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
		randomIntInRange(88, 128),
	)
}

func ensureScheme(url string, forceHTTPS bool) string {
	if !strings.Contains(url, "://") {
		url = "https://" + url
	} else if forceHTTPS && strings.HasPrefix(url, "http://") {
		url = "https://" + url[7:]
	}
	return url
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
	if filename != "" {
		file, err := os.Create(filename)
		if err != nil {
			log.Errorf("Error creating output file: %v", err)
		}
		return bufio.NewWriter(file)
	}
	return bufio.NewWriter(os.Stdout)
}

func urlJoin(baseURL, relativePath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	relative, err := url.Parse(relativePath)
	if err != nil {
		return "", err
	}
	joined := base.ResolveReference(relative)
	joined.Path = path.Join(base.Path, relative.Path)
	return joined.String(), nil
}

func saveFile(initialBody []byte, resp *http.Response, saveDirectory string) {
	u := resp.Request.URL

	host := u.Hostname()
	path := u.Path

	savePath := filepath.Join(saveDirectory, host, path)
	savePath = strings.TrimSuffix(savePath, "/")

	err := os.MkdirAll(filepath.Dir(savePath), 0755)
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
		return ranges, nil // Нет фильтра, возвращаем пустой диапазон
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
