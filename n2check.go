package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "1.2.0"

var fixedStable = [3]int{1, 30, 7}
var fixedMainline = [3]int{1, 31, 9}

type cveDef struct {
	ID    string
	Title string
	First [3]int
}

var cveDefs = []cveDef{
	{"CVE-2026-123007", "переполнение в HTTP/2 flow control", [3]int{1, 9, 5}},
	{"CVE-2026-123634", "use-after-free в DNS resolver", [3]int{0, 6, 18}},
	{"CVE-2026-123633", "use-after-free в HTTP/2 (upstream)", [3]int{1, 19, 7}},
	{"CVE-2026-121810", "use-after-free в HTTP/3 (upstream)", [3]int{1, 25, 0}},
	{"CVE-2026-113425", "use-after-free в mail proxy (auth_http)", [3]int{0, 5, 33}},
}

var debianFixed = map[string]string{
	"bookworm": "1.22.1-9+deb12u11",
	"trixie":   "1.26.3-3+deb13u11",
	"forky":    "1.30.6-4",
	"sid":      "1.30.6-4",
	"stonking": "1.30.4-7ubuntu1.2",
	"resolute": "1.28.3-2ubuntu1.13",
	"noble":    "1.24.0-2ubuntu7.20",
	"jammy":    "1.18.0-6ubuntu14.23",
	"focal":    "1.18.0-0ubuntu1.7+esm5",
	"bionic":   "1.14.0-0ubuntu1.11+esm6",
	"xenial":   "1.10.3-0ubuntu0.16.04.5+esm11",
	"trusty":   "1.4.6-1ubuntu3.9+esm10",
}

var debianAdvisory = map[string]string{
	"bookworm": "DLA-4918-1",
	"trixie":   "DSA-6642-1",
	"forky":    "",
	"sid":      "",
	"stonking": "USN-9159-1",
	"resolute": "USN-9159-1",
	"noble":    "USN-9159-1",
	"jammy":    "USN-9159-1",
	"focal":    "USN-9159-1",
	"bionic":   "USN-9159-1",
	"xenial":   "USN-9159-1",
	"trusty":   "USN-9159-1",
}

var alpineFixed = map[string]string{
	"edge": "1.30.7-r0",
	"3.24": "1.30.7-r0",
	"3.23": "1.28.3-r8",
	"3.22": "1.28.3-r8",
	"3.21": "1.26.3-r4",
}

var suseFixed = map[string]string{
	"150400": "1.21.5-150400.3.28.1",
	"150600": "1.21.5-150600.10.30.1",
}

var (
	versionPattern      = regexp.MustCompile(`(^|[^0-9.])([0-9]+)\.([0-9]+)\.([0-9]+)([^0-9.]|$)`)
	nginxVersionPattern = regexp.MustCompile(`(?i)nginx/([0-9]+\.[0-9]+\.[0-9]+)`)
	h3Pattern           = regexp.MustCompile(`(^|,)\s*h3(-[0-9]+)?\s*=`)
	cvePattern          = regexp.MustCompile(`(?i)CVE-2026-(123007|123634|123633|121810|113425)`)
	n2rootTextPattern   = regexp.MustCompile(`(?i)nginx2root|flow[- ]control window overflow`)
	controlPattern      = regexp.MustCompile(`[\x00-\x20\x7f]`)
)

type CveRow struct {
	Cve           string `json:"cve"`
	Title         string `json:"title"`
	VersionStatus string `json:"version_status"`
	Exposure      string `json:"exposure"`
	Detail        string `json:"detail"`
}

type BuildFlags struct {
	HTTPV2Module bool `json:"http_v2_module"`
	HTTPV3Module bool `json:"http_v3_module"`
	MailModule   bool `json:"mail_module"`
}

type ConfigFeatures struct {
	HTTP2                bool `json:"http2"`
	HTTP2On              bool `json:"http2_on"`
	HTTP2Off             bool `json:"http2_off"`
	HTTP2Listen          bool `json:"http2_listen"`
	HTTP3                bool `json:"http3"`
	HTTP3On              bool `json:"http3_on"`
	HTTP3Off             bool `json:"http3_off"`
	QUICListen           bool `json:"quic_listen"`
	Resolver             bool `json:"resolver"`
	VariableProxyPass    bool `json:"variable_proxy_pass"`
	Upstream             bool `json:"upstream"`
	Mirror               bool `json:"mirror"`
	MirrorRequestBodyOff bool `json:"mirror_request_body_off"`
	SSI                  bool `json:"ssi"`
	MailBlock            bool `json:"mail_block"`
	MailProxyOn          bool `json:"mail_proxy_on"`
	AuthHTTP             bool `json:"auth_http"`
}

type PackageInfo struct {
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Suite        string   `json:"suite,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Advisory     string   `json:"advisory,omitempty"`
	Status       string   `json:"status"`
	Source       string   `json:"source"`
	FixedCves    []string `json:"fixed_cves,omitempty"`
	Note         string   `json:"note,omitempty"`
}

type Advisory struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Kernel      string `json:"kernel,omitempty"`
	Loaded      bool   `json:"loaded"`
	Builtin     bool   `json:"builtin"`
	Blocked     bool   `json:"blocked"`
	Blacklisted bool   `json:"blacklisted"`
}

type Report struct {
	URL             string          `json:"url,omitempty"`
	PatchStatus     string          `json:"patch_status"`
	NginxVersion    *string         `json:"nginx_version"`
	Reason          string          `json:"reason"`
	ExitCode        int             `json:"exit_code"`
	Server          string          `json:"server,omitempty"`
	HTTPStatus      int             `json:"http_status,omitempty"`
	HTTP2           *bool           `json:"http2,omitempty"`
	HTTP3Advertised *bool           `json:"http3_advertised,omitempty"`
	ALPN            string          `json:"alpn,omitempty"`
	ALPNError       string          `json:"alpn_error,omitempty"`
	Caveat          string          `json:"caveat,omitempty"`
	Note            string          `json:"note,omitempty"`
	Cves            []CveRow        `json:"cves"`
	Build           *BuildFlags     `json:"build,omitempty"`
	Config          *ConfigFeatures `json:"config,omitempty"`
	ConfigError     string          `json:"config_error,omitempty"`
	BuildError      string          `json:"build_error,omitempty"`
	Package         *PackageInfo    `json:"package,omitempty"`
	PackageVersion  string          `json:"package_version,omitempty"`
	Advisories      []Advisory      `json:"advisories,omitempty"`
	local           bool
}

func compareV(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func versionAffected(v, first [3]int) bool {
	if compareV(v, first) < 0 {
		return false
	}
	if compareV(v, fixedMainline) >= 0 {
		return false
	}
	if compareV(v, fixedStable) >= 0 && compareV(v, [3]int{1, 31, 0}) < 0 {
		return false
	}
	return true
}

func parseVersion(text string) ([3]int, bool) {
	match := versionPattern.FindStringSubmatch(text)
	if match == nil {
		return [3]int{}, false
	}
	major, err1 := strconv.Atoi(match[2])
	minor, err2 := strconv.Atoi(match[3])
	patch, err3 := strconv.Atoi(match[4])
	if err1 != nil || err2 != nil || err3 != nil {
		return [3]int{}, false
	}
	return [3]int{major, minor, patch}, true
}

func extractNginxVersion(text string) string {
	match := nginxVersionPattern.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return match[1]
}

func assessVersion(v [3]int, known bool) (string, []CveRow) {
	rows := make([]CveRow, 0, len(cveDefs))
	vulnerable := false
	for _, def := range cveDefs {
		row := CveRow{Cve: def.ID, Title: def.Title, VersionStatus: "unknown", Exposure: "unknown"}
		if known {
			if versionAffected(v, def.First) {
				row.VersionStatus = "vulnerable"
				vulnerable = true
			} else {
				row.VersionStatus = "ok"
				row.Detail = "версия вне уязвимого диапазона"
			}
		}
		rows = append(rows, row)
	}
	if !known {
		return "unknown", rows
	}
	if vulnerable {
		return "vulnerable", rows
	}
	return "ok", rows
}

func applicableCves(version string) map[string]bool {
	result := map[string]bool{}
	v, known := parseVersion(version)
	_, rows := assessVersion(v, known)
	for _, row := range rows {
		if row.VersionStatus == "vulnerable" {
			result[row.Cve] = true
		}
	}
	return result
}

func sortedSet(set map[string]bool) []string {
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }

func exitCode(status string) int {
	switch status {
	case "ok":
		return 0
	case "vulnerable":
		return 1
	default:
		return 3
	}
}

func newReport(status string, versionText *string, errMsg string) *Report {
	report := &Report{
		PatchStatus:  status,
		NginxVersion: versionText,
		ExitCode:     exitCode(status),
		Cves:         []CveRow{},
	}
	if errMsg != "" {
		report.Reason = errMsg
	} else if versionText != nil {
		report.Reason = "nginx " + *versionText
	} else {
		report.Reason = "Версия nginx не найдена"
	}
	return report
}

func setStatus(report *Report, status string) {
	report.PatchStatus = status
	report.ExitCode = exitCode(status)
}

func setVersion(report *Report, versionText string) {
	report.NginxVersion = stringPtr(versionText)
	report.Reason = "nginx " + versionText
}

func runCommand(timeout time.Duration, name string, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err == nil {
		return output.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output.String(), exitErr.ExitCode()
	}
	return output.String(), -1
}

func lastTextLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

// ---------- HTTP / TLS ----------

func fetchHeaders(rawURL string, timeout time.Duration, insecure bool) (http.Header, int, error) {
	if controlPattern.MatchString(rawURL) {
		return nil, 0, errors.New("URL содержит пробелы или управляющие символы")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, 0, errors.New("Используйте URL вида http:// или https://")
	}
	if parsed.Hostname() == "" {
		return nil, 0, errors.New("URL не содержит хоста")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, 0, errors.New("Учётные данные и фрагменты в URL не поддерживаются")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, // --insecure
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var lastErr error
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		request, err := http.NewRequest(method, rawURL, nil)
		if err != nil {
			return nil, 0, err
		}
		request.Header.Set("User-Agent", "n2check/"+version)
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
			if method == http.MethodHead {
				continue
			}
			return nil, 0, err
		}
		headers := response.Header.Clone()
		statusCode := response.StatusCode
		response.Body.Close()
		if method == http.MethodGet || (statusCode != http.StatusMethodNotAllowed &&
			statusCode != http.StatusNotImplemented) {
			return headers, statusCode, nil
		}
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("не удалось получить ответ")
}

func detectALPN(parsed *url.URL, timeout time.Duration, insecure bool) (string, string) {
	if parsed.Scheme != "https" {
		return "", "ALPN проверяется только для https"
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: timeout}
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure, // --insecure
		NextProtos:         []string{"h2", "http/1.1"},
	}
	connection, err := tls.DialWithDialer(
		dialer, "tcp", net.JoinHostPort(host, port), config,
	)
	if err != nil {
		return "", err.Error()
	}
	defer connection.Close()
	return connection.ConnectionState().NegotiatedProtocol, ""
}

func applyRemoteExposures(rows []CveRow, http2 *bool, http3 *bool, alpnError string) {
	http2Value, http2Known := false, false
	if http2 != nil {
		http2Value, http2Known = *http2, true
	}
	http3Value, http3Known := false, false
	if http3 != nil {
		http3Value, http3Known = *http3, true
	}
	for i := range rows {
		row := &rows[i]
		if row.VersionStatus != "vulnerable" {
			if row.VersionStatus == "ok" {
				row.Exposure = "not_applicable"
				row.Detail = "версия вне уязвимого диапазона"
			}
			continue
		}
		switch row.Cve {
		case "CVE-2026-123007":
			if http2Known && http2Value {
				row.Exposure = "exposed"
				row.Detail = "сервер согласовал HTTP/2 по ALPN (h2)"
			} else if http2Known {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/2 не согласован по ALPN"
			} else {
				row.Exposure = "unknown"
				row.Detail = alpnError
				if row.Detail == "" {
					row.Detail = "HTTP/2 не проверен"
				}
			}
		case "CVE-2026-123633":
			if http2Known && http2Value {
				row.Exposure = "possible"
				row.Detail = "HTTP/2 включён; наличие upstream проверяется по конфигурации"
			} else if http2Known {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/2 не согласован по ALPN"
			} else {
				row.Exposure = "unknown"
				row.Detail = alpnError
				if row.Detail == "" {
					row.Detail = "HTTP/2 не проверен"
				}
			}
		case "CVE-2026-121810":
			if http3Known && http3Value {
				row.Exposure = "possible"
				row.Detail = "HTTP/3 рекламируется в Alt-Svc; наличие upstream проверяется по конфигурации"
			} else {
				row.Exposure = "unknown"
				row.Detail = "HTTP/3 удалённо не подтверждён; отсутствие Alt-Svc ничего не доказывает"
			}
		case "CVE-2026-123634":
			row.Exposure = "unknown"
			row.Detail = "нужны resolver, proxy_pass с переменной и subrequest — конфигурация не видна удалённо"
		case "CVE-2026-113425":
			row.Exposure = "unknown"
			row.Detail = "нужен mail proxy с proxy on и auth_http — конфигурация не видна удалённо"
		}
	}
}

func checkURL(rawURL string, timeout time.Duration, insecure bool) *Report {
	report := newReport("unknown", nil, "")
	headers, statusCode, err := fetchHeaders(rawURL, timeout, insecure)
	if err != nil {
		report.Reason = err.Error()
		return report
	}
	server := headers.Get("Server")
	altSvc := headers.Get("Alt-Svc")
	report.Server = server
	report.HTTPStatus = statusCode
	http3 := altSvc != "" && h3Pattern.MatchString(altSvc)
	report.HTTP3Advertised = boolPtr(http3)

	nginxVersion := extractNginxVersion(server)
	if nginxVersion != "" {
		v, known := parseVersion(nginxVersion)
		status, rows := assessVersion(v, known)
		setStatus(report, status)
		setVersion(report, nginxVersion)
		report.Cves = rows
	}

	parsed, _ := url.Parse(rawURL)
	alpn, alpnError := detectALPN(parsed, timeout, insecure)
	if alpnError != "" {
		report.ALPNError = alpnError
	} else {
		report.ALPN = alpn
		report.HTTP2 = boolPtr(alpn == "h2")
	}
	applyRemoteExposures(report.Cves, report.HTTP2, report.HTTP3Advertised, alpnError)

	if report.PatchStatus == "vulnerable" {
		report.Caveat = "Версия из баннера может не учитывать бэкпорт дистрибутива; для Debian проверьте пакет локально: --local."
	}
	if nginxVersion == "" {
		if server != "" {
			report.Note = "Версия nginx не найдена в заголовке Server (server_tokens off, CDN или другой сервер)"
		} else {
			report.Note = "Заголовок Server отсутствует"
		}
	}
	return report
}

// ---------- nginx config ----------

const directiveStart = `(?m)(^|[;{}])\s*`

func hasDirective(config, pattern string) bool {
	re, err := regexp.Compile(directiveStart + pattern)
	if err != nil {
		return false
	}
	return re.MatchString(config)
}

func stripComments(text string) string {
	var builder strings.Builder
	runes := []rune(text)
	var quote rune
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if quote != 0 {
			builder.WriteRune(ch)
			if ch == '\\' && i+1 < len(runes) {
				i++
				builder.WriteRune(runes[i])
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			builder.WriteRune(ch)
			continue
		}
		if ch == '#' {
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
			if i < len(runes) {
				builder.WriteRune('\n')
			}
			continue
		}
		builder.WriteRune(ch)
	}
	return builder.String()
}

func parseConfig(text string) ConfigFeatures {
	config := stripComments(text)
	http2On := hasDirective(config, `http2\s+on\s*;`)
	http2Off := hasDirective(config, `http2\s+off\s*;`)
	http2Listen := hasDirective(config, `listen\s+[^;]*\bhttp2\b[^;]*;`)
	http3On := hasDirective(config, `http3\s+on\s*;`)
	http3Off := hasDirective(config, `http3\s+off\s*;`)
	quicListen := hasDirective(config, `listen\s+[^;]*\bquic\b[^;]*;`)
	return ConfigFeatures{
		HTTP2:                http2On || http2Listen,
		HTTP2On:              http2On,
		HTTP2Off:             http2Off,
		HTTP2Listen:          http2Listen,
		HTTP3:                http3On || quicListen,
		HTTP3On:              http3On,
		HTTP3Off:             http3Off,
		QUICListen:           quicListen,
		Resolver:             hasDirective(config, `resolver\s+[^;]+;`),
		VariableProxyPass:    hasDirective(config, `proxy_pass\s+[^;]*\$[^;]*;`),
		Upstream:             hasDirective(config, `(proxy|grpc|fastcgi|uwsgi|scgi)_pass\s+[^;]+;`),
		Mirror:               hasDirective(config, `mirror\s+[^;]+;`),
		MirrorRequestBodyOff: hasDirective(config, `mirror_request_body\s+off\s*;`),
		SSI:                  hasDirective(config, `ssi\s+on\s*;`),
		MailBlock:            hasDirective(config, `mail\s*\{`),
		MailProxyOn:          hasDirective(config, `proxy\s+on\s*;`),
		AuthHTTP:             hasDirective(config, `auth_http\s+[^;]+;`),
	}
}

func parseBuildFlags(text string) BuildFlags {
	return BuildFlags{
		HTTPV2Module: strings.Contains(text, "--with-http_v2_module"),
		HTTPV3Module: strings.Contains(text, "--with-http_v3_module"),
		MailModule:   strings.Contains(text, "--with-mail"),
	}
}

func applyLocalExposures(rows []CveRow, features ConfigFeatures, configRead bool,
	flags BuildFlags, buildKnown bool) {
	for i := range rows {
		row := &rows[i]
		if row.VersionStatus != "vulnerable" {
			if row.VersionStatus == "ok" {
				row.Exposure = "not_applicable"
				row.Detail = "версия вне уязвимого диапазона"
			}
			continue
		}
		switch row.Cve {
		case "CVE-2026-123007":
			if buildKnown && !flags.HTTPV2Module {
				row.Exposure = "not_exposed"
				row.Detail = "сборка без --with-http_v2_module"
			} else if configRead && !features.HTTP2 {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/2 не включён в конфигурации"
			} else if configRead && features.HTTP2 {
				row.Exposure = "exposed"
				row.Detail = "HTTP/2 включён в конфигурации"
			} else {
				row.Exposure = "unknown"
				row.Detail = "конфигурация недоступна, модуль HTTP/2 не проверен"
			}
		case "CVE-2026-123633":
			if buildKnown && !flags.HTTPV2Module {
				row.Exposure = "not_exposed"
				row.Detail = "сборка без --with-http_v2_module"
			} else if configRead && !features.HTTP2 {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/2 не включён в конфигурации"
			} else if configRead && features.HTTP2 && features.Upstream {
				row.Exposure = "possible"
				row.Detail = "HTTP/2 включён и есть proxy_pass/grpc_pass на upstream"
			} else if configRead && features.HTTP2 {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/2 включён, но forwarding на upstream не найден"
			} else {
				row.Exposure = "unknown"
				row.Detail = "конфигурация недоступна, HTTP/2/upstream не проверены"
			}
		case "CVE-2026-121810":
			if buildKnown && !flags.HTTPV3Module {
				row.Exposure = "not_exposed"
				row.Detail = "сборка без --with-http_v3_module"
			} else if configRead && !features.HTTP3 {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/3/QUIC не включён в конфигурации"
			} else if configRead && features.HTTP3 && features.Upstream {
				row.Exposure = "possible"
				row.Detail = "HTTP/3 включён и есть forwarding на upstream"
			} else if configRead && features.HTTP3 {
				row.Exposure = "not_exposed"
				row.Detail = "HTTP/3 включён, но forwarding на upstream не найден"
			} else {
				row.Exposure = "unknown"
				row.Detail = "конфигурация недоступна, HTTP/3/upstream не проверены"
			}
		case "CVE-2026-123634":
			if !configRead {
				row.Exposure = "unknown"
				row.Detail = "конфигурация недоступна"
			} else if !features.Resolver || !features.VariableProxyPass {
				row.Exposure = "not_exposed"
				row.Detail = "нет resolver и/или proxy_pass с переменной"
			} else if features.Mirror || features.SSI {
				row.Exposure = "possible"
				row.Detail = "есть resolver, proxy_pass с переменной и subrequest (mirror/SSI)"
			} else {
				row.Exposure = "possible"
				row.Detail = "есть resolver и proxy_pass с переменной; проверьте subrequest-директивы"
			}
		case "CVE-2026-113425":
			if buildKnown && !flags.MailModule {
				row.Exposure = "not_exposed"
				row.Detail = "сборка без --with-mail"
			} else if !configRead {
				row.Exposure = "unknown"
				row.Detail = "конфигурация недоступна"
			} else if features.MailBlock && features.MailProxyOn && features.AuthHTTP {
				row.Exposure = "exposed"
				row.Detail = "mail-блок с proxy on и auth_http"
			} else if features.MailBlock {
				row.Exposure = "not_exposed"
				row.Detail = "mail-блок есть, но proxy on и/или auth_http не найдены"
			} else {
				row.Exposure = "not_exposed"
				row.Detail = "mail-блок не найден"
			}
		}
	}
}

// ---------- OS / packages ----------

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func osRelease() map[string]string {
	result := map[string]string{}
	data := readText("/etc/os-release")
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		result[key] = strings.Trim(value, `"'`)
	}
	return result
}

func osFamily() string {
	data := osRelease()
	if len(data) == 0 {
		if runtime.GOOS == "freebsd" {
			return "freebsd"
		}
		return ""
	}
	identifier := strings.ToLower(data["ID"])
	names := map[string]bool{identifier: true}
	for _, part := range strings.Fields(strings.ToLower(data["ID_LIKE"])) {
		names[part] = true
	}
	if identifier == "freebsd" || runtime.GOOS == "freebsd" {
		return "freebsd"
	}
	if names["ubuntu"] {
		return "ubuntu"
	}
	if names["debian"] || names["raspbian"] {
		return "debian"
	}
	if names["alpine"] {
		return "alpine"
	}
	if names["arch"] {
		return "arch"
	}
	if names["sles"] || names["suse"] || names["opensuse"] ||
		names["opensuse-leap"] || names["opensuse-tumbleweed"] {
		return "suse"
	}
	for _, name := range []string{"rhel", "fedora", "centos", "rocky",
		"almalinux", "oracle", "ol", "amzn", "amazon"} {
		if names[name] {
			return "rpm"
		}
	}
	return ""
}

func debianSuite() string {
	data := osRelease()
	identifier := strings.ToLower(data["ID"])
	if identifier != "debian" && identifier != "raspbian" && identifier != "ubuntu" {
		return ""
	}
	if suite := data["VERSION_CODENAME"]; suite != "" {
		return suite
	}
	return data["DEBIAN_CODENAME"]
}

func simpleDebianCompare(left, right string) int {
	leftVersion, leftOK := parseVersion(left)
	rightVersion, rightOK := parseVersion(right)
	if !leftOK || !rightOK {
		return 0
	}
	if cmp := compareV(leftVersion, rightVersion); cmp != 0 {
		return cmp
	}
	updateRe := regexp.MustCompile(`(?i)u([0-9]+)`)
	leftUpdate := updateRe.FindStringSubmatch(left)
	rightUpdate := updateRe.FindStringSubmatch(right)
	if leftUpdate != nil && rightUpdate != nil {
		leftNumber, _ := strconv.Atoi(leftUpdate[1])
		rightNumber, _ := strconv.Atoi(rightUpdate[1])
		if leftNumber < rightNumber {
			return -1
		}
		if leftNumber > rightNumber {
			return 1
		}
	}
	revisionRe := regexp.MustCompile(`-([0-9]+)(\+|$)`)
	leftRevision := revisionRe.FindStringSubmatch(left)
	rightRevision := revisionRe.FindStringSubmatch(right)
	if leftRevision != nil && rightRevision != nil {
		leftNumber, _ := strconv.Atoi(leftRevision[1])
		rightNumber, _ := strconv.Atoi(rightRevision[1])
		if leftNumber < rightNumber {
			return -1
		}
		if leftNumber > rightNumber {
			return 1
		}
	}
	if left == right {
		return 0
	}
	if left < right {
		return -1
	}
	return 1
}

func compareDebianVersions(left, right string) int {
	_, code := runCommand(5*time.Second, "dpkg", "--compare-versions", left, "ge", right)
	switch code {
	case 0:
		return 1
	case 1:
		return -1
	default:
		return simpleDebianCompare(left, right)
	}
}

func debianPackageInfo(pkg, version, suite string) *PackageInfo {
	if suite == "" {
		if strings.Contains(version, "deb12") {
			suite = "bookworm"
		} else if strings.Contains(version, "deb13") {
			suite = "trixie"
		} else if strings.HasPrefix(version, "1.30.6-4") {
			suite = "sid"
		} else if strings.HasPrefix(version, "1.30.6-3") {
			suite = "forky"
		}
	}
	fixed := debianFixed[suite]
	info := &PackageInfo{
		Package: pkg, Version: version, Suite: suite,
		FixedVersion: fixed, Advisory: debianAdvisory[suite],
		Status: "unknown", Source: "dpkg",
	}
	if fixed == "" {
		return info
	}
	installedVersion, installedOK := parseVersion(version)
	fixedVersion, fixedOK := parseVersion(fixed)
	if !installedOK || !fixedOK {
		return info
	}
	switch compareV(installedVersion, fixedVersion) {
	case -1:
		info.Status = "vulnerable"
		return info
	case 1:
		info.Note = "пакет не из ветки Debian/Ubuntu-исправления; вердикт по upstream-версии"
		return info
	}
	switch compareDebianVersions(version, fixed) {
	case 1:
		info.Status = "fixed"
		info.FixedCves = sortedSet(applicableCves(version))
	case -1:
		info.Status = "vulnerable"
	}
	return info
}

func localPackage() (string, string, bool) {
	for _, pkg := range []string{"nginx", "nginx-core", "nginx-full", "nginx-light"} {
		output, code := runCommand(5*time.Second, "dpkg-query", "-W", "-f=${Version}", pkg)
		output = strings.TrimSpace(output)
		if code == 0 && output != "" {
			return pkg, output, true
		}
	}
	output, code := runCommand(5*time.Second, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "nginx")
	output = strings.TrimSpace(output)
	if code == 0 && output != "" {
		return "nginx", output, true
	}
	return "", "", false
}

func parseRPMQuery(output string) (string, string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\t") {
			parts := strings.SplitN(line, "\t", 2)
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	return "", ""
}

func simpleRPMCompare(left, right string) int {
	split := func(value string) (int, [3]int, string) {
		value = strings.TrimSpace(value)
		epoch := 0
		if idx := strings.Index(value, ":"); idx >= 0 {
			if number, err := strconv.Atoi(value[:idx]); err == nil {
				epoch = number
			}
			value = value[idx+1:]
		}
		versionPart := value
		release := ""
		if idx := strings.LastIndex(value, "-"); idx >= 0 {
			versionPart = value[:idx]
			release = value[idx+1:]
		}
		versionValue, _ := parseVersion(versionPart)
		return epoch, versionValue, release
	}
	leftEpoch, leftVersion, leftRelease := split(left)
	rightEpoch, rightVersion, rightRelease := split(right)
	if leftEpoch != rightEpoch {
		if leftEpoch > rightEpoch {
			return 1
		}
		return -1
	}
	if cmp := compareV(leftVersion, rightVersion); cmp != 0 {
		return cmp
	}
	tokenRe := regexp.MustCompile(`[0-9]+|[A-Za-z]+`)
	leftTokens := tokenRe.FindAllString(leftRelease, -1)
	rightTokens := tokenRe.FindAllString(rightRelease, -1)
	max := len(leftTokens)
	if len(rightTokens) > max {
		max = len(rightTokens)
	}
	for i := 0; i < max; i++ {
		leftToken, rightToken := "0", "0"
		if i < len(leftTokens) {
			leftToken = leftTokens[i]
		}
		if i < len(rightTokens) {
			rightToken = rightTokens[i]
		}
		leftNumber, leftErr := strconv.Atoi(leftToken)
		rightNumber, rightErr := strconv.Atoi(rightToken)
		if leftErr == nil && rightErr == nil {
			if leftNumber != rightNumber {
				if leftNumber > rightNumber {
					return 1
				}
				return -1
			}
			continue
		}
		if leftToken != rightToken {
			if leftToken > rightToken {
				return 1
			}
			return -1
		}
	}
	return 0
}

func changelogCves(text string) map[string]bool {
	result := map[string]bool{}
	for _, match := range cvePattern.FindAllString(text, -1) {
		result[strings.ToUpper(match)] = true
	}
	return result
}

func rpmPackageInfo(nginxBin string) *PackageInfo {
	path := nginxBin
	if resolved, err := exec.LookPath(nginxBin); err == nil {
		path = resolved
	}
	pkg, version := "", ""
	output, code := runCommand(10*time.Second, "rpm", "-q", "--qf",
		"%{NAME}\t%{VERSION}-%{RELEASE}\n", "-f", path)
	if code == 0 {
		pkg, version = parseRPMQuery(output)
	}
	if pkg == "" {
		for _, candidate := range []string{"nginx", "nginx-core", "nginx-full", "nginx-light"} {
			output, code = runCommand(10*time.Second, "rpm", "-q", "--qf",
				"%{NAME}\t%{VERSION}-%{RELEASE}", candidate)
			if code == 0 {
				pkg, version = parseRPMQuery(output)
				if pkg != "" {
					break
				}
			}
		}
	}
	if pkg == "" || version == "" {
		return nil
	}

	data := osRelease()
	suite := strings.TrimSpace(data["ID"] + " " + data["VERSION_ID"])
	if suite == "" {
		suite = "rpm"
	}
	applicable := applicableCves(version)
	changelog, _ := runCommand(10*time.Second, "rpm", "-q", "--changelog", pkg)
	found := changelogCves(changelog)
	if len(found) == 0 && n2rootTextPattern.MatchString(changelog) {
		found["CVE-2026-123007"] = true
	}
	fixed := map[string]bool{}
	for cve := range found {
		if applicable[cve] {
			fixed[cve] = true
		}
	}

	status := "unknown"
	source := "upstream"
	upstreamStatus := upstreamPackageStatus(version)
	switch {
	case len(applicable) == 0 && upstreamStatus == "fixed":
		status = "fixed"
		source = "upstream"
	case len(applicable) > 0 && len(fixed) == len(applicable):
		status = "fixed"
		source = "rpm-changelog"
	case len(fixed) > 0:
		status = "partial"
		source = "rpm-changelog"
	default:
		status = upstreamStatus
		if status == "fixed" {
			fixed = applicable
		}
	}

	info := &PackageInfo{
		Package: pkg, Version: version, Suite: suite,
		Status: status, Source: source, FixedCves: sortedSet(fixed),
	}
	if status != "fixed" && osFamily() == "suse" {
		release := version
		if idx := strings.LastIndex(version, "-"); idx >= 0 {
			release = version[idx+1:]
		}
		branch := strings.SplitN(release, ".", 2)[0]
		if candidate := suseFixed[branch]; candidate != "" &&
			simpleRPMCompare(version, candidate) >= 0 {
			info.Status = "fixed"
			info.Source = "suse-advisory"
			info.FixedVersion = candidate
			info.FixedCves = sortedSet(applicable)
		}
	}
	if strings.ToLower(data["ID"]) == "centos" && info.Status != "fixed" {
		info.Note = "CentOS Linux 7/8 EOL и официальных фиксов не получает; для CentOS Stream ждите RHEL-сборку или проверьте rpm -q --changelog nginx"
	}
	return info
}

func upstreamPackageStatus(version string) string {
	v, known := parseVersion(version)
	if !known {
		return "unknown"
	}
	if !versionAffected(v, [3]int{1, 9, 5}) {
		return "fixed"
	}
	return "vulnerable"
}

func alpineVersionKey(value string) ([4]int, bool) {
	pattern := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(-r([0-9]+))?`)
	match := pattern.FindStringSubmatch(value)
	if match == nil {
		return [4]int{}, false
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	revision := 0
	if match[5] != "" {
		revision, _ = strconv.Atoi(match[5])
	}
	return [4]int{major, minor, patch, revision}, true
}

func simpleAlpineCompare(left, right string) int {
	leftKey, leftOK := alpineVersionKey(left)
	rightKey, rightOK := alpineVersionKey(right)
	if !leftOK || !rightOK {
		return 0
	}
	for i := 0; i < 4; i++ {
		if leftKey[i] < rightKey[i] {
			return -1
		}
		if leftKey[i] > rightKey[i] {
			return 1
		}
	}
	return 0
}

func alpinePackageInfo() *PackageInfo {
	version := ""
	output, code := runCommand(10*time.Second, "apk", "info", "-v", "nginx")
	if code == 0 {
		match := regexp.MustCompile(`nginx-([0-9]+\.[0-9]+\.[0-9]+(-r[0-9]+)?)`).FindStringSubmatch(output)
		if match != nil {
			version = match[1]
		}
	}
	if version == "" {
		output, code = runCommand(10*time.Second, "apk", "list", "--installed", "nginx")
		if code == 0 {
			match := regexp.MustCompile(`nginx-([0-9]+\.[0-9]+\.[0-9]+(-r[0-9]+)?)`).FindStringSubmatch(output)
			if match != nil {
				version = match[1]
			}
		}
	}
	if version == "" {
		return nil
	}

	branch := ""
	release := readText("/etc/alpine-release")
	if match := regexp.MustCompile(`^([0-9]+\.[0-9]+)`).FindStringSubmatch(release); match != nil {
		branch = match[1]
	}
	if branch == "" && strings.Contains(readText("/etc/apk/repositories"), "edge") {
		branch = "edge"
	}
	fixed := alpineFixed[branch]
	info := &PackageInfo{
		Package: "nginx", Version: version, Suite: branch,
		FixedVersion: fixed, Advisory: "Alpine secdb", Source: "apk",
		Status: "unknown",
	}
	applicable := applicableCves(version)
	if fixed != "" {
		switch simpleAlpineCompare(version, fixed) {
		case 0, 1:
			info.Status = "fixed"
			info.FixedCves = sortedSet(applicable)
		case -1:
			info.Status = "vulnerable"
		}
		return info
	}
	info.Status = upstreamPackageStatus(version)
	info.Source = "upstream"
	if info.Status == "fixed" {
		info.FixedCves = sortedSet(applicable)
	}
	return info
}

func pacmanPackageInfo() *PackageInfo {
	pkg, version := "nginx", ""
	for _, candidate := range []string{"nginx", "nginx-mainline"} {
		output, code := runCommand(5*time.Second, "pacman", "-Q", candidate)
		if code != 0 {
			continue
		}
		fields := strings.Fields(output)
		if len(fields) >= 2 {
			pkg, version = fields[0], fields[1]
			break
		}
	}
	if version == "" {
		return nil
	}
	status := upstreamPackageStatus(version)
	info := &PackageInfo{
		Package: pkg, Version: version, Suite: "Arch Linux",
		FixedVersion: "1.30.7 / 1.31.9", Status: status, Source: "pacman",
	}
	if status == "fixed" {
		info.FixedCves = sortedSet(applicableCves(version))
	}
	return info
}

func freebsdPackageInfo() *PackageInfo {
	version := ""
	for _, pkg := range []string{"nginx", "nginx-devel"} {
		output, code := runCommand(5*time.Second, "pkg", "query", "%v", pkg)
		output = strings.TrimSpace(output)
		if code == 0 && output != "" && !strings.HasPrefix(output, "pkg:") {
			version = strings.Split(output, "\n")[0]
			break
		}
	}
	if version == "" {
		return nil
	}
	status := upstreamPackageStatus(version)
	info := &PackageInfo{
		Package: "nginx", Version: version, Suite: "FreeBSD",
		FixedVersion: "1.30.7 / 1.31.9", Status: status, Source: "pkg",
	}
	if status == "fixed" {
		info.FixedCves = sortedSet(applicableCves(version))
	}
	return info
}

func packageStatus(nginxBin string) *PackageInfo {
	switch osFamily() {
	case "debian", "ubuntu":
		if pkg, pkgVersion, ok := localPackage(); ok {
			return debianPackageInfo(pkg, pkgVersion, debianSuite())
		}
		return nil
	case "rpm", "suse":
		return rpmPackageInfo(nginxBin)
	case "alpine":
		return alpinePackageInfo()
	case "arch":
		return pacmanPackageInfo()
	case "freebsd":
		return freebsdPackageInfo()
	}
	if pkg, pkgVersion, ok := localPackage(); ok {
		return debianPackageInfo(pkg, pkgVersion, debianSuite())
	}
	return rpmPackageInfo(nginxBin)
}

func kernelSCTPAdvisory() Advisory {
	item := Advisory{ID: "SCTP", Title: "SCTP в ядре (LPE до root)", Status: "unknown"}
	if runtime.GOOS != "linux" {
		item.Status = "not_applicable"
		item.Detail = "не Linux (" + runtime.GOOS + ")"
		return item
	}
	release := strings.TrimSpace(readText("/proc/sys/kernel/osrelease"))
	kernel, known := parseVersion(release)
	if !known {
		match := regexp.MustCompile(`^([0-9]+)\.([0-9]+)`).FindStringSubmatch(release)
		if match != nil {
			major, _ := strconv.Atoi(match[1])
			minor, _ := strconv.Atoi(match[2])
			kernel = [3]int{major, minor, 0}
			known = true
		}
	}
	item.Kernel = release
	if known && compareV(kernel, [3]int{4, 15, 0}) < 0 {
		item.Status = "not_applicable"
		item.Detail = "ядро " + release + " старше 4.15 — цепочка неприменима"
		return item
	}

	loaded := regexp.MustCompile(`(?m)^sctp\s`).MatchString(readText("/proc/modules"))
	builtin := false
	if !loaded {
		builtin = regexp.MustCompile(`(?mi)^SCTP\s`).MatchString(readText("/proc/net/protocols"))
	}
	blocked := false
	blacklisted := false
	files, _ := filepath.Glob("/etc/modprobe.d/*.conf")
	for _, path := range files {
		text := readText(path)
		if regexp.MustCompile(`(?m)^\s*install\s+sctp\s+/bin/false\b`).MatchString(text) {
			blocked = true
		}
		if regexp.MustCompile(`(?m)^\s*blacklist\s+sctp\b`).MatchString(text) {
			blacklisted = true
		}
	}
	switch {
	case builtin:
		item.Status = "warning"
		item.Detail = "SCTP встроен в ядро " + release + "; цепочка nginx2root → root возможна"
	case loaded:
		item.Status = "warning"
		item.Detail = "модуль sctp загружен; цепочка nginx2root → root возможна"
	case blocked:
		item.Status = "ok"
		item.Detail = "загрузка sctp заблокирована через modprobe.d"
	case blacklisted:
		item.Status = "warning"
		item.Detail = "sctp только в blacklist: явный modprobe всё равно загрузит модуль; надёжнее install sctp /bin/false"
	default:
		item.Status = "warning"
		item.Detail = "модуль sctp не загружен, но может загрузиться автоматически; если SCTP не нужен, добавьте install sctp /bin/false"
	}
	item.Loaded = loaded
	item.Builtin = builtin
	item.Blocked = blocked
	item.Blacklisted = blacklisted
	return item
}

func checkLocal(nginxBin string) *Report {
	report := newReport("unknown", nil, "")
	report.local = true
	output, code := runCommand(15*time.Second, nginxBin, "-v")
	if code != 0 {
		report.Reason = strings.TrimSpace(output)
		if report.Reason == "" && code == -1 {
			report.Reason = "Не найден исполняемый файл: " + nginxBin
		}
		if report.Reason == "" {
			report.Reason = fmt.Sprintf("%s -v завершился с кодом %d", nginxBin, code)
		}
		return report
	}
	nginxVersion := extractNginxVersion(output)
	if nginxVersion == "" {
		report.Reason = "не удалось определить версию nginx из `nginx -v`"
		return report
	}
	v, known := parseVersion(nginxVersion)
	status, rows := assessVersion(v, known)
	setStatus(report, status)
	setVersion(report, nginxVersion)
	report.Cves = rows

	pkg := packageStatus(nginxBin)
	if pkg != nil {
		report.Package = pkg
		report.PackageVersion = pkg.Version
	}

	buildOutput, buildCode := runCommand(15*time.Second, nginxBin, "-V")
	buildKnown := buildCode == 0
	flags := BuildFlags{}
	if buildKnown {
		flags = parseBuildFlags(buildOutput)
		report.Build = &flags
	} else {
		report.BuildError = strings.TrimSpace(buildOutput)
		if report.BuildError == "" {
			report.BuildError = fmt.Sprintf("код %d", buildCode)
		}
	}

	configOutput, configCode := runCommand(15*time.Second, nginxBin, "-T")
	configRead := configCode == 0
	features := ConfigFeatures{}
	if configRead {
		features = parseConfig(configOutput)
		report.Config = &features
	} else {
		report.ConfigError = lastTextLine(configOutput)
		if report.ConfigError == "" {
			report.ConfigError = fmt.Sprintf("`nginx -T` завершился с кодом %d", configCode)
		}
	}
	applyLocalExposures(rows, features, configRead, flags, buildKnown)

	if pkg != nil {
		fixed := map[string]bool{}
		for _, cve := range pkg.FixedCves {
			fixed[cve] = true
		}
		if len(fixed) > 0 {
			note := "исправлено в пакете " + pkg.Version
			if pkg.Suite != "" {
				note += " (" + pkg.Suite + ")"
			}
			if pkg.Advisory != "" {
				note += ", advisory " + pkg.Advisory
			}
			for i := range rows {
				if rows[i].VersionStatus == "vulnerable" && fixed[rows[i].Cve] {
					rows[i].VersionStatus = "ok"
					rows[i].Exposure = "not_applicable"
					rows[i].Detail = note
				}
			}
		}
		if pkg.Status == "fixed" {
			setStatus(report, "ok")
		}
	}
	report.Cves = rows
	report.Advisories = []Advisory{kernelSCTPAdvisory()}
	return report
}

// ---------- output / CLI ----------

var exposureLabels = map[string]string{
	"exposed":        "EXPOSED",
	"possible":       "POSSIBLE",
	"not_exposed":    "NOT EXPOSED",
	"unknown":        "UNKNOWN",
	"not_applicable": "NOT APPLICABLE",
}

func yesNo(value bool) string {
	if value {
		return "да"
	}
	return "нет"
}

func printCves(rows []CveRow) {
	for _, row := range rows {
		label := exposureLabels[row.Exposure]
		if label == "" {
			label = row.Exposure
		}
		fmt.Printf("  %s (%s): %s — %s\n", row.Cve, row.Title, label, row.Detail)
	}
}

func printURLDetails(report *Report) {
	if report.Server != "" {
		fmt.Printf("  Server: %s\n", report.Server)
	}
	if report.HTTP2 != nil {
		if *report.HTTP2 {
			fmt.Println("  HTTP/2: да (ALPN h2)")
		} else {
			fmt.Println("  HTTP/2: нет (ALPN не h2)")
		}
	} else {
		suffix := report.ALPNError
		if suffix != "" {
			fmt.Printf("  HTTP/2: не проверен — %s\n", suffix)
		} else {
			fmt.Println("  HTTP/2: не проверен")
		}
	}
	if report.HTTP3Advertised != nil && *report.HTTP3Advertised {
		fmt.Println("  HTTP/3: рекламируется в Alt-Svc")
	} else {
		fmt.Println("  HTTP/3: не рекламируется (отсутствие Alt-Svc не доказывает отсутствие QUIC)")
	}
	if report.Caveat != "" {
		fmt.Printf("  Примечание: %s\n", report.Caveat)
	}
	if report.Note != "" {
		fmt.Printf("  Примечание: %s\n", report.Note)
	}
	printCves(report.Cves)
}

func packageStatusLabel(status string) string {
	switch status {
	case "fixed":
		return "исправлено"
	case "partial":
		return "исправлено частично"
	case "vulnerable":
		return "уязвимо"
	default:
		return "не удалось сравнить"
	}
}

func printLocalDetails(report *Report) {
	if report.Build != nil {
		fmt.Printf("  Сборка: HTTP/2=%s, HTTP/3=%s, mail=%s\n",
			yesNo(report.Build.HTTPV2Module),
			yesNo(report.Build.HTTPV3Module),
			yesNo(report.Build.MailModule))
	}
	if report.Config != nil {
		fmt.Printf("  Конфигурация: HTTP/2=%s, HTTP/3=%s, resolver=%s, proxy_pass с переменной=%s, mirror=%s, mail proxy=%s\n",
			yesNo(report.Config.HTTP2),
			yesNo(report.Config.HTTP3),
			yesNo(report.Config.Resolver),
			yesNo(report.Config.VariableProxyPass),
			yesNo(report.Config.Mirror),
			yesNo(report.Config.MailProxyOn))
	}
	if report.ConfigError != "" {
		fmt.Printf("  Конфигурация недоступна: %s\n", report.ConfigError)
	}
	if report.BuildError != "" {
		fmt.Printf("  Сборка не определена: %s\n", report.BuildError)
	}
	printCves(report.Cves)
	if report.Package != nil {
		pkg := report.Package
		line := "  Пакет: " + pkg.Package + " " + pkg.Version
		if pkg.Suite != "" {
			line += " (" + pkg.Suite + ")"
		}
		line += " — " + packageStatusLabel(pkg.Status)
		if pkg.FixedVersion != "" {
			line += "; исправление: " + pkg.FixedVersion
		}
		if pkg.Advisory != "" {
			line += " (" + pkg.Advisory + ")"
		}
		if pkg.Source != "" {
			line += " [" + pkg.Source + "]"
		}
		fmt.Println(line)
		if pkg.Note != "" {
			fmt.Printf("  Примечание: %s\n", pkg.Note)
		}
	}
	for _, item := range report.Advisories {
		fmt.Printf("  %s: %s — %s\n", item.Title, strings.ToUpper(item.Status), item.Detail)
	}
}

func printResult(report *Report, rawURL string, verbose bool) int {
	if rawURL != "" {
		report.URL = rawURL
	}
	var output strings.Builder
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	prefix := ""
	if rawURL != "" {
		prefix = rawURL + " — "
	}
	if jsonOutput {
		fmt.Print(output.String())
	} else {
		fmt.Printf("%s%s: %s\n", prefix, strings.ToUpper(report.PatchStatus), report.Reason)
		if verbose {
			if report.local {
				printLocalDetails(report)
			} else {
				printURLDetails(report)
			}
		}
	}
	return report.ExitCode
}

var jsonOutput bool

func readURLs(path string) ([]string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	urls := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" && !seen[line] {
			seen[line] = true
			urls = append(urls, line)
		}
	}
	return urls, nil
}

func runBulk(urls []string, threads int, timeout time.Duration,
	insecure bool) int {
	jobs := make(chan string)
	codes := make(chan int, len(urls))
	var waitGroup sync.WaitGroup
	var printMutex sync.Mutex

	for i := 0; i < threads; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for rawURL := range jobs {
				report := checkURL(rawURL, timeout, insecure)
				printMutex.Lock()
				code := printResult(report, rawURL, false)
				printMutex.Unlock()
				codes <- code
			}
		}()
	}
	go func() {
		for _, rawURL := range urls {
			jobs <- rawURL
		}
		close(jobs)
		waitGroup.Wait()
		close(codes)
	}()

	aggregate := 0
	for code := range codes {
		if code == 1 {
			aggregate = 1
		} else if code == 3 && aggregate != 1 {
			aggregate = 3
		}
	}
	return aggregate
}

const usage = `Использование: n2check URL [--timeout СЕКУНДЫ] [--insecure] [--json]
               n2check --local [--nginx ПУТЬ] [--json]
               n2check --file ФАЙЛ [--threads N] [--async] [--timeout СЕКУНДЫ] [--insecure] [--json]
               n2check --version`

func usageError(message string) int {
	fmt.Fprintln(os.Stderr, message)
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

func normalizeArgs(args []string) []string {
	valueFlags := map[string]bool{
		"nginx": true, "timeout": true, "file": true, "threads": true,
	}
	flagArgs := []string{}
	positionals := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagArgs = append(flagArgs, arg)
			name := strings.TrimLeft(arg, "-")
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if valueFlags[name] && !strings.Contains(arg, "=") {
				if i+1 < len(args) {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flagArgs, positionals...)
}

func run(args []string) int {
	flags := flag.NewFlagSet("n2check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, usage)
	}
	local := flags.Bool("local", false, "проверить локальный nginx")
	nginxBin := flags.String("nginx", "nginx", "путь к nginx")
	timeoutSeconds := flags.Float64("timeout", 10, "таймаут в секундах")
	file := flags.String("file", "", "файл со списком URL")
	threads := flags.Int("threads", 1, "число одновременных проверок")
	async := flags.Bool("async", false, "асинхронный режим (goroutines)")
	jsonFlag := flags.Bool("json", false, "JSON-вывод")
	insecure := flags.Bool("insecure", false, "не проверять TLS-сертификат")
	showVersion := flags.Bool("version", false, "показать версию")

	if err := flags.Parse(normalizeArgs(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	jsonOutput = *jsonFlag

	positionals := flags.Args()
	if len(positionals) > 1 {
		return usageError("Можно указать только один URL")
	}
	address := ""
	if len(positionals) == 1 {
		address = positionals[0]
	}
	modes := 0
	if address != "" {
		modes++
	}
	if *file != "" {
		modes++
	}
	if *local {
		modes++
	}
	if modes != 1 {
		return usageError("Укажите что-то одно: URL, --file или --local")
	}

	threadsSet := false
	nginxSet := false
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "threads" {
			threadsSet = true
		}
		if flag.Name == "nginx" {
			nginxSet = true
		}
	})
	if *async && *file == "" {
		return usageError("--async можно использовать только вместе с --file")
	}
	if threadsSet && *file == "" {
		return usageError("--threads можно использовать только вместе с --file")
	}
	if nginxSet && !*local {
		return usageError("--nginx можно использовать только вместе с --local")
	}
	if *insecure && *local {
		return usageError("--insecure можно использовать только с URL или --file")
	}
	if *threads < 1 {
		return usageError("--threads должен быть целым числом от 1")
	}
	timeout := time.Duration(*timeoutSeconds * float64(time.Second))
	if !*local && !(*timeoutSeconds > 0 && *timeoutSeconds <= 60) {
		return usageError("--timeout должен быть больше 0 и не больше 60 секунд")
	}

	if *local {
		report := checkLocal(*nginxBin)
		return printResult(report, "", true)
	}
	if *file != "" {
		urls, err := readURLs(*file)
		if err != nil {
			return usageError("Не удалось прочитать файл со списком: " + err.Error())
		}
		if len(urls) == 0 {
			return usageError("Файл не содержит ни одного URL")
		}
		return runBulk(urls, *threads, timeout, *insecure)
	}
	report := checkURL(address, timeout, *insecure)
	return printResult(report, "", true)
}

func main() {
	os.Exit(run(os.Args[1:]))
}
