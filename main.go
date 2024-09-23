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

	writer := createWriter(*outputFile)
	defer writer.Flush()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *workers)

	log.Info("Scanning started!")

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
				userAgent := randomChromeUserAgent()
				log.Debugf("User-Agent for %s: %s", fullURL, userAgent)
				req.Header.Set("User-Agent", userAgent)
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
				resp, err := client.Do(req)
				if err != nil {
					log.Warnf("Error probing URL %s: %v", fullURL, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != 200 {
					log.Warnf("Bad status code for URL %s: %d", fullURL, resp.StatusCode)
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

				body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
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
					Input:          fullURL,                                                                     // Входной URL
					URL:            resp.Request.URL.String(),                                                   // Конечный URL
					Method:         req.Method,                                                                  // Метод запроса
					Host:           resp.Request.URL.Host,                                                       // Хост ответа
					Path:           strings.TrimRight(resp.Request.URL.Path+"?"+resp.Request.URL.RawQuery, "?"), // Путь с query string
					CompletionDate: completionDate,                                                              // Дата завершения запроса
					Status:         resp.StatusCode,                                                             // Статус ответа
					ContentType:    mimeType,                                                                    // Content-Type
					ContentLength:  resp.ContentLength,                                                          // Длина контента
					IP:             ip,                                                                          // IP-адрес
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
					saveFile(resp, body, *saveDirectory)
				}
			}(url, path)
		}
	}

	wg.Wait()
	log.Infof("Scanning finished!")
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
func expandBraces(expression string) []string {
	var expandedSet = make(map[string]bool)

	var dfs func(exp string)
	dfs = func(exp string) {
		// Find the position of the first closing brace
		closingBraceIndex := strings.Index(exp, "}")

		// Base case: If there is no closing brace, add the entire expression to the set
		if closingBraceIndex == -1 {
			expandedSet[exp] = true
			return
		}

		// Find the position of the last opening brace before the found closing brace
		openingBraceIndex := strings.LastIndex(exp[:closingBraceIndex], "{")

		// Divide the expression into three parts: before, inside, and after the braces
		beforeBrace := exp[:openingBraceIndex]
		afterBrace := exp[closingBraceIndex+1:]

		// Split the contents of the braces by commas and recurse for each part
		for _, insideBrace := range strings.Split(exp[openingBraceIndex+1:closingBraceIndex], ",") {
			// Recursively call the dfs function with the new expression
			dfs(beforeBrace + insideBrace + afterBrace)
		}
	}

	// Call the dfs helper function with the initial expression
	dfs(expression)

	// Convert the set to a sorted slice
	var result []string
	for key := range expandedSet {
		result = append(result, key)
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
		randomIntInRange(100, 128),
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

func saveFile(resp *http.Response, partialBody []byte, saveDirectory string) {
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
	_, err = file.Write(partialBody)
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
