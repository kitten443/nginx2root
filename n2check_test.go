package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		input string
		want  [3]int
		ok    bool
	}{
		{"nginx/1.31.8", [3]int{1, 31, 8}, true},
		{"1.18.0-6ubuntu14.22", [3]int{1, 18, 0}, true},
		{"nginx", [3]int{}, false},
		{"1.31.8.1", [3]int{}, false},
	}
	for _, test := range cases {
		got, ok := parseVersion(test.input)
		if ok != test.ok || got != test.want {
			t.Errorf("parseVersion(%q) = %v, %v; want %v, %v",
				test.input, got, ok, test.want, test.ok)
		}
	}
}

func TestVersionAffected(t *testing.T) {
	cases := []struct {
		version [3]int
		first   [3]int
		want    bool
	}{
		{[3]int{1, 9, 4}, [3]int{1, 9, 5}, false},
		{[3]int{1, 9, 5}, [3]int{1, 9, 5}, true},
		{[3]int{1, 30, 6}, [3]int{1, 9, 5}, true},
		{[3]int{1, 30, 7}, [3]int{1, 9, 5}, false},
		{[3]int{1, 31, 8}, [3]int{1, 9, 5}, true},
		{[3]int{1, 31, 9}, [3]int{1, 9, 5}, false},
		{[3]int{0, 6, 17}, [3]int{0, 6, 18}, false},
		{[3]int{0, 6, 18}, [3]int{0, 6, 18}, true},
		{[3]int{1, 19, 6}, [3]int{1, 19, 7}, false},
		{[3]int{1, 19, 7}, [3]int{1, 19, 7}, true},
		{[3]int{1, 24, 9}, [3]int{1, 25, 0}, false},
		{[3]int{1, 25, 0}, [3]int{1, 25, 0}, true},
		{[3]int{0, 5, 32}, [3]int{0, 5, 33}, false},
		{[3]int{0, 5, 33}, [3]int{0, 5, 33}, true},
	}
	for _, test := range cases {
		if got := versionAffected(test.version, test.first); got != test.want {
			t.Errorf("versionAffected(%v, %v) = %v; want %v",
				test.version, test.first, got, test.want)
		}
	}
}

func TestAssessVersion(t *testing.T) {
	status, rows := assessVersion([3]int{1, 31, 8}, true)
	if status != "vulnerable" || len(rows) != 5 {
		t.Fatalf("assessVersion(1.31.8) = %q, %d rows", status, len(rows))
	}
	for _, row := range rows {
		if row.VersionStatus != "vulnerable" {
			t.Errorf("%s status = %s", row.Cve, row.VersionStatus)
		}
	}

	status, rows = assessVersion([3]int{1, 30, 7}, true)
	if status != "ok" {
		t.Fatalf("assessVersion(1.30.7) = %q", status)
	}
	for _, row := range rows {
		if row.VersionStatus != "ok" {
			t.Errorf("%s status = %s", row.Cve, row.VersionStatus)
		}
	}

	status, _ = assessVersion([3]int{0, 5, 32}, true)
	if status != "ok" {
		t.Errorf("assessVersion(0.5.32) = %q", status)
	}
}

func TestConfigParsing(t *testing.T) {
	config := `
http {
    server {
        listen 443 ssl;
        http2 on;
        resolver 1.1.1.1;
        location / {
            proxy_pass http://$host;
            mirror /mirror;
        }
        location = /mirror {
            internal;
            mirror_request_body off;
            proxy_pass http://backend;
        }
    }
}
mail {
    proxy on;
    auth_http http://auth/check;
}
`
	features := parseConfig(config)
	if !features.HTTP2 || !features.Resolver || !features.VariableProxyPass ||
		!features.Upstream || !features.Mirror || !features.MirrorRequestBodyOff ||
		!features.MailBlock || !features.MailProxyOn || !features.AuthHTTP {
		t.Fatalf("unexpected config features: %+v", features)
	}
	if features.HTTP3 {
		t.Error("HTTP/3 should be disabled")
	}

	inline := parseConfig(`http { server { listen 443 quic reuseport; http3 on; } }`)
	if !inline.HTTP3 || !inline.QUICListen {
		t.Errorf("inline HTTP/3 not detected: %+v", inline)
	}
	legacy := parseConfig(`http { server { listen 443 ssl http2; } }`)
	if !legacy.HTTP2 || !legacy.HTTP2Listen || legacy.HTTP2On {
		t.Errorf("legacy HTTP/2 listen not detected: %+v", legacy)
	}
}

func TestStripComments(t *testing.T) {
	text := "http2 on; # выключить\nadd_header X \"#keep\";\n"
	stripped := stripComments(text)
	if strings.Contains(stripped, "# выключить") {
		t.Error("comment was not stripped")
	}
	if !strings.Contains(stripped, "#keep") {
		t.Error("quoted hash was stripped")
	}
}

func TestRemoteExposures(t *testing.T) {
	_, rows := assessVersion([3]int{1, 31, 8}, true)
	http2 := true
	http3 := false
	applyRemoteExposures(rows, &http2, &http3, "")
	byID := map[string]CveRow{}
	for _, row := range rows {
		byID[row.Cve] = row
	}
	if byID["CVE-2026-123007"].Exposure != "exposed" {
		t.Errorf("123007 exposure = %q", byID["CVE-2026-123007"].Exposure)
	}
	if byID["CVE-2026-123633"].Exposure != "possible" {
		t.Errorf("123633 exposure = %q", byID["CVE-2026-123633"].Exposure)
	}
	if byID["CVE-2026-121810"].Exposure != "unknown" {
		t.Errorf("121810 exposure = %q", byID["CVE-2026-121810"].Exposure)
	}
}

func TestLocalExposures(t *testing.T) {
	features := parseConfig(`
http {
    server {
        listen 443 ssl;
        http2 on;
        resolver 1.1.1.1;
        location / { proxy_pass http://$host; mirror /mirror; }
    }
}
mail { proxy on; auth_http http://auth/check; }
`)
	flags := BuildFlags{HTTPV2Module: true, HTTPV3Module: true, MailModule: true}
	_, rows := assessVersion([3]int{1, 31, 8}, true)
	applyLocalExposures(rows, features, true, flags, true)
	byID := map[string]CveRow{}
	for _, row := range rows {
		byID[row.Cve] = row
	}
	if byID["CVE-2026-123007"].Exposure != "exposed" {
		t.Errorf("123007 exposure = %q", byID["CVE-2026-123007"].Exposure)
	}
	if byID["CVE-2026-123634"].Exposure != "possible" {
		t.Errorf("123634 exposure = %q", byID["CVE-2026-123634"].Exposure)
	}
	if byID["CVE-2026-121810"].Exposure != "not_exposed" {
		t.Errorf("121810 exposure = %q", byID["CVE-2026-121810"].Exposure)
	}
	if byID["CVE-2026-113425"].Exposure != "exposed" {
		t.Errorf("113425 exposure = %q", byID["CVE-2026-113425"].Exposure)
	}
}

func TestDebianPackageInfo(t *testing.T) {
	fixed := debianPackageInfo("nginx", "1.22.1-9+deb12u11", "bookworm")
	if fixed.Status != "fixed" {
		t.Fatalf("bookworm fixed status = %q", fixed.Status)
	}
	if !containsString(fixed.FixedCves, "CVE-2026-123007") ||
		containsString(fixed.FixedCves, "CVE-2026-121810") {
		t.Errorf("unexpected fixed CVEs: %v", fixed.FixedCves)
	}

	vulnerable := debianPackageInfo("nginx", "1.22.1-9+deb12u9", "bookworm")
	if vulnerable.Status != "vulnerable" {
		t.Errorf("bookworm vulnerable status = %q", vulnerable.Status)
	}

	ubuntu := debianPackageInfo("nginx", "1.18.0-6ubuntu14.23", "jammy")
	if ubuntu.Status != "fixed" || ubuntu.Advisory != "USN-9159-1" {
		t.Errorf("ubuntu package = %+v", ubuntu)
	}

	nginxOrg := debianPackageInfo("nginx", "1.31.8-1~bookworm", "bookworm")
	if nginxOrg.Status != "unknown" {
		t.Errorf("nginx.org package status = %q", nginxOrg.Status)
	}
}

func containsString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func TestSimpleRPMCompare(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.20.1-32.el9_9.2", "1.20.1-32.el9_9.1", 1},
		{"1.20.1-32.el9_9.1", "1.20.1-32.el9_9.2", -1},
		{"1.21.5-150400.3.28.1", "1.21.5-150400.3.27.1", 1},
		{"1.26.3-10.module+el9.9.0+25360+9b756829.4",
			"1.26.3-10.module+el9.9.0+25360+9b756829.4", 0},
	}
	for _, test := range cases {
		if got := simpleRPMCompare(test.left, test.right); got != test.want {
			t.Errorf("simpleRPMCompare(%q, %q) = %d; want %d",
				test.left, test.right, got, test.want)
		}
	}
}

func TestAlpineCompare(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.30.7-r0", "1.30.7-r0", 0},
		{"1.28.3-r8", "1.28.3-r7", 1},
		{"1.26.3-r3", "1.26.3-r4", -1},
	}
	for _, test := range cases {
		if got := simpleAlpineCompare(test.left, test.right); got != test.want {
			t.Errorf("simpleAlpineCompare(%q, %q) = %d; want %d",
				test.left, test.right, got, test.want)
		}
	}
}

func TestChangelogCves(t *testing.T) {
	cves := changelogCves("Resolves: CVE-2026-123007\nResolves: CVE-2026-123633")
	if !cves["CVE-2026-123007"] || !cves["CVE-2026-123633"] {
		t.Errorf("changelog CVEs = %v", cves)
	}
}

func TestNormalizeArgs(t *testing.T) {
	got := normalizeArgs([]string{"https://example.com", "--timeout", "5", "--json"})
	want := []string{"--timeout", "5", "--json", "https://example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeArgs = %v; want %v", got, want)
	}
	got = normalizeArgs([]string{"--timeout=5", "--file", "-"})
	want = []string{"--timeout=5", "--file", "-"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeArgs = %v; want %v", got, want)
	}
}

func TestCheckLocalFakeNginx(t *testing.T) {
	directory := t.TempDir()
	script := `#!/bin/sh
case "$1" in
  -v) echo "nginx version: nginx/1.31.8" >&2 ;;
  -V) echo "configure arguments: --with-http_v2_module --with-http_v3_module --with-mail" >&2 ;;
  -T) cat <<'EOF'
http {
    server {
        listen 443 ssl;
        http2 on;
        resolver 1.1.1.1;
        location / {
            proxy_pass http://$host;
            mirror /mirror;
        }
    }
}
mail {
    proxy on;
    auth_http http://auth/check;
}
EOF
    ;;
esac
`
	path := filepath.Join(directory, "nginx")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeDpkg := filepath.Join(directory, "dpkg-query")
	if err := os.WriteFile(fakeDpkg, []byte("#!/bin/sh\necho '1.22.1-9+deb12u9'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	report := checkLocal(path)
	if report.PatchStatus != "vulnerable" {
		t.Errorf("status = %q", report.PatchStatus)
	}
	if report.NginxVersion == nil || *report.NginxVersion != "1.31.8" {
		t.Errorf("version = %v", report.NginxVersion)
	}
	if report.Config == nil || !report.Config.HTTP2 || !report.Config.Resolver {
		t.Errorf("config = %+v", report.Config)
	}
}
