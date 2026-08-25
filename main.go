package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// ================= CONFIG & CONSTANTS =================

type Mode string

const (
	ModeDirect Mode = "direct"
	ModeAuto   Mode = "autonomous"

	FrameData         = 0x00
	FrameHeaders      = 0x01
	FrameRSTStream    = 0x03
	FrameSettings     = 0x04
	FrameGoAway       = 0x07
	FrameWindowUpdate = 0x08
	FrameContinuation = 0x09

	FlagEndStream  = 0x01
	FlagEndHeaders = 0x04
	FlagPadded     = 0x08
	FlagPriority   = 0x20
	FlagAck        = 0x01

	LimitMaxIPs     = 262144
	LimitValidPairs = 10000
	MaxHostsPer24   = 254
	MaxSampled24    = 4

	// Public recursive resolvers with documented ECS-capable endpoints.
	// Google Public DNS supports ECS; Quad9 exposes dedicated ECS endpoints.
	// OpenDNS is kept as an optional fallback for availability, but we do not
	// assume it will forward a caller-supplied ECS option.
	DefaultDNSResolvers = "8.8.8.8,8.8.4.4,9.9.9.11,149.112.112.11,9.9.9.12,149.112.112.12,208.67.222.222,208.67.220.220"
)

var (
	cdnStrong = []string{"cloudflare", "fastly", "akamai", "ddos-guard", "qrator", "sucuri"}
	cdnWeak   = []string{"x-cache", "x-served-by", "x-edge"}

	bannedTLDs = map[string]bool{
		"crl": true, "ocsp": true, "der": true, "crt": true, "cer": true, "pem": true,
		"arpa": true, "local": true, "internal": true, "invalid": true, "example": true, "test": true, "localhost": true,
	}

	junkTLDs = []string{".xyz", ".top", ".site", ".fun", ".online", ".space", ".pw", ".cc", ".icu", ".click", ".win", ".bid", ".date"}
	dynDNS   = []string{"duckdns.org", "mooo.com", "ddns.net", "freeddns.org", "crabdance.com", "eu.org", "cloudns.cc", "hopto.org", "zapto.org", "sytes.net", "dyn.com", "no-ip.org"}

	domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	numRe    = regexp.MustCompile(`(?i)(^|\.)\d+\.[a-z]{2,}$`)

	ErrDNSNXDomain = errors.New("NXDOMAIN")

	uaRng *rand.Rand
	uaMu  sync.Mutex
)

type Config struct {
	Mode              Mode
	Workers           int
	DNSWorkers        int
	MaxIPs            int
	TCPTimeoutMs      int
	TLSTimeoutMs      int
	H2ReadTimeoutMs   int
	H2WriteTimeoutMs  int
	DNSQueryTimeoutMs int
	ECSIP             string
	ECSPrefix         int
	DNSResolvers      []string
	DNSTrace          bool
	DNSTraceLimit     int
	Seed              int64
	TargetASN         string
	TargetCountry     string
	TargetIP          string
	DirectSNI         string
	CIDRs             []string
	Domains           []string
	NoPTR             bool
	NoActiveTLS       bool
}

// ================= EVIDENCE =================

type DomainSource uint32

const (
	SourceSeed DomainSource = 1 << iota
	SourcePTR
	SourceDirectTLS
)

func (s DomainSource) Has(flag DomainSource) bool { return s&flag != 0 }

type Evidence struct {
	Direct    DomainSource
	Inherited DomainSource
}

func (e Evidence) Combined() DomainSource { return e.Direct | e.Inherited }

// ================= MODELS =================

type Timings struct {
	TCP          time.Duration
	TLS          time.Duration
	H2FirstFrame time.Duration
	H2Headers    time.Duration
}

func (t Timings) TotalProbeLatency() time.Duration { return t.TCP + t.TLS + t.H2Headers }

type PeerSettingsProfile struct {
	HeaderTableSize         uint32
	EnablePush              uint32
	MaxConcurrentStreams    uint32
	InitialWindowSize       uint32
	MaxFrameSize            uint32
	MaxHeaderListSize       uint32
	HasHeaderTableSize      bool
	HasEnablePush           bool
	HasMaxConcurrentStreams bool
	HasInitialWindowSize    bool
	HasMaxFrameSize         bool
	HasMaxHeaderListSize    bool
}

type RealityScore struct {
	TLSQuality     float64
	Certificate    float64
	H2Profile      float64
	ServerProfile  float64
	HTTPBehavior   float64
	DiscoveryScore float64
	Latency        float64
	Total          float64
}

type CDNStatus string

const (
	CDNConfirmed     CDNStatus = "Confirmed"
	CDNLikely        CDNStatus = "Likely"
	CDNStatusUnknown CDNStatus = "Unknown"
)

type Candidate struct {
	IP                    string
	SNI                   string
	ALPN                  string
	H2HeadersReceived     bool
	ResponseHeadersParsed bool
	ResponseTrailersSeen  bool
	H2ProtocolConfirmed   bool
	TLS13                 bool
	HTTPStatus            int
	Location              string
	BodyBytes             int
	Server                string
	ContentType           string
	Timings               Timings
	CDNProvider           string
	CDNStatus             CDNStatus
	Score                 float64
	DomainPenalty         float64
	RealityScore          RealityScore
	CertChainValid        bool
	EndStreamSeen         bool
	StreamReset           bool
	GoAwaySeen            bool
	Evidence              DomainSource
	DomainQuality         string
	CertIssuer            string
	CertSubject           string
	CertSANCount          int
	CertValidTime         bool
	CertSNIMatch          bool
	SettingsFramesCount   int
	SettingsAckCount      int
	SettingsChanges       int
	H2SettingsReceived    bool
	H2SettingsAckSent     bool
	H2SettingsAckReceived bool
	InitialPeerSettings   PeerSettingsProfile
	LatestPeerSettings    PeerSettingsProfile
	H2DataFrames          int

	HPACKErrors   bool
	MissingStatus bool
	ReadTimeout   bool
}

type TargetPair struct {
	IP       string
	SNI      string
	Evidence DomainSource
}

// ================= TELEMETRY & CACHES =================

type PipelineStats struct {
	mu            sync.Mutex
	IPSampled     int
	ActiveProbes  int
	UniqueDomains int

	// DNS
	DNSQueries            int
	DNSSuccess            int
	DNSFailed             int
	DNSNXDomain           int
	DNSTimeout            int
	DNSTemporary          int
	DNSOtherErr           int
	DNSNoIPv4             int
	DNSResolvedIPs        int
	DNSUniqueResolvedIPs  int
	DNSUniqueTargetIPs    int
	DNSTargetRangeMatches int
	DNSTargetDomains      int
	DNSValidPairs         int

	// PTR
	PTRQueriesSent int
	PTRFound       int
	PTRErrors      int

	// TCP
	TCPConnected int
	TCPTimeouts  int
	TCPRefused   int
	TCPOtherErrs int

	// TLS
	TLSHandshake          int
	TLSTimeouts           int
	TLSValidationFailures int
	NoPeerCertificates    int
	TLSHandshakeFailure   int
	TLSUnrecognizedName   int
	TLSConnectionReset    int
	TLSEOF                int
	TLSOtherErrs          int

	// H2
	H2NoALPN          int
	H2ProtocolOK      int
	H2TimeoutNoFrames int
	H2ConnectionReset int
	H2BrokenPipe      int
	H2BadRequest      int
	H2GoAway          int
	H2EOF             int
	H2TLSAlerts       int
	H2OtherErrs       int

	H2HeadersOK   int
	H2Timeouts    int
	H2HPACKErrors int

	H2StatusOK      int
	H2InvalidStatus int
	EndStreamOK     int

	// Final
	ScoreRejected      int
	CandidatesAccepted int

	IPWithPTR       int
	IPWithDirectTLS int
}

func NewPipelineStats() *PipelineStats {
	return &PipelineStats{}
}

type DNSResolverStat struct {
	Attempts int
	Answers  int
	NXDomain int
	Failures int
	Timeouts int
	IPv4s    int
}

type RuntimeCaches struct {
	DNSCache         *SafeDNSCache
	DNSGroup         *singleflight.Group
	DNSStatsMu       sync.Mutex
	DNSResolverStats map[string]*DNSResolverStat
	DNSTraceMu       sync.Mutex
	DNSTraceSeen     map[string]struct{}
	DNSTracePrinted  int
}

func NewRuntimeCaches() *RuntimeCaches {
	return &RuntimeCaches{
		DNSCache:         NewSafeDNSCache(),
		DNSGroup:         &singleflight.Group{},
		DNSResolverStats: make(map[string]*DNSResolverStat),
		DNSTraceSeen:     make(map[string]struct{}),
	}
}

func (r *RuntimeCaches) dnsResolverStat(resolver string) *DNSResolverStat {
	r.DNSStatsMu.Lock()
	defer r.DNSStatsMu.Unlock()
	stat, ok := r.DNSResolverStats[resolver]
	if !ok {
		stat = &DNSResolverStat{}
		r.DNSResolverStats[resolver] = stat
	}
	return stat
}

type DNSCacheEntry struct {
	IPs      []string
	NXDomain bool
	Expires  time.Time
}

type SafeDNSCache struct {
	mu   sync.RWMutex
	data map[string]*DNSCacheEntry
}

func NewSafeDNSCache() *SafeDNSCache {
	return &SafeDNSCache{data: make(map[string]*DNSCacheEntry)}
}

func (c *SafeDNSCache) Get(key string) (*DNSCacheEntry, bool) {
	c.mu.RLock()
	v, ok := c.data[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(v.Expires) {
		c.mu.Lock()
		if v2, ok2 := c.data[key]; ok2 && time.Now().After(v2.Expires) {
			delete(c.data, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	var ips []string
	if v.IPs != nil {
		ips = append([]string(nil), v.IPs...)
	}
	return &DNSCacheEntry{IPs: ips, NXDomain: v.NXDomain}, true
}

func (c *SafeDNSCache) Put(key string, entry *DNSCacheEntry, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ips []string
	if entry.IPs != nil {
		ips = append([]string(nil), entry.IPs...)
	}
	c.data[key] = &DNSCacheEntry{IPs: ips, NXDomain: entry.NXDomain, Expires: time.Now().Add(ttl)}
}

// ================= API HELPERS (RIPE & IP-API) =================

func getPublicIP(targetIP string) (string, error) {
	if targetIP != "" {
		ip := net.ParseIP(targetIP)
		if ip != nil && ip.To4() != nil {
			return ip.To4().String(), nil
		}
		return "", fmt.Errorf("invalid target IPv4 format: %s", targetIP)
	}
	urls := []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, u := range urls {
		resp, err := client.Get(u)
		if err == nil {
			defer resp.Body.Close()
			ipBytes, _ := io.ReadAll(resp.Body)
			ipStr := strings.TrimSpace(string(ipBytes))
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.To4() != nil {
				return ip.To4().String(), nil
			}
		}
	}
	return "", fmt.Errorf("could not determine public IPv4. Please provide it manually via -vps-ip")
}

func getCountry(ip string) string {
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode", ip))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			CountryCode string `json:"countryCode"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			return strings.ToUpper(result.CountryCode)
		}
	}
	return "UNKNOWN"
}

func getASNAndPrefix(ip string) (string, string) {
	var asn, prefix string
	client := &http.Client{Timeout: 6 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", ip))
	if err == nil {
		var result struct {
			Data struct {
				ASNs   []interface{} `json:"asns"`
				Prefix string        `json:"prefix"`
			} `json:"data"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if len(result.Data.ASNs) > 0 {
			asn = fmt.Sprintf("%v", result.Data.ASNs[0])
			if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
				asn = "AS" + asn
			}
		}
		prefix = result.Data.Prefix
	}

	if asn == "" {
		resp2, err2 := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=as", ip))
		if err2 == nil {
			var res2 struct {
				AS string `json:"as"`
			}
			json.NewDecoder(resp2.Body).Decode(&res2)
			resp2.Body.Close()

			if res2.AS != "" {
				parts := strings.Split(res2.AS, " ")
				if len(parts) > 0 {
					asn = strings.ToUpper(parts[0])
					if !strings.HasPrefix(asn, "AS") {
						asn = "AS" + asn
					}
				}
			}
		}
	}

	if asn == "" {
		asn = "UNKNOWN_ASN"
	}

	if prefix == "" {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			parsedIP = parsedIP.To4()
			if parsedIP != nil {
				prefix = fmt.Sprintf("%d.%d.%d.0/24", parsedIP[0], parsedIP[1], parsedIP[2])
			}
		}
	}

	return asn, prefix
}

func getPrefixes(asn string) []string {
	if asn == "UNKNOWN_ASN" {
		return nil
	}

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s", asn))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	var prefixes []string
	for _, p := range result.Data.Prefixes {
		if !strings.Contains(p.Prefix, ":") {
			prefixes = append(prefixes, p.Prefix)
		}
	}
	return prefixes
}

func filterPrefixesByCountry(prefixes []string, targetCountry string) []string {
	if targetCountry == "" || len(prefixes) == 0 || targetCountry == "UNKNOWN" {
		return prefixes
	}
	targetCountry = strings.ToUpper(targetCountry)

	type QueryItem struct {
		Query string `json:"query"`
	}

	queryToPrefix := make(map[string]string)
	var allQueries []QueryItem

	for _, p := range prefixes {
		ip, _, err := net.ParseCIDR(p)
		if err == nil {
			qIP := ip.String()
			queryToPrefix[qIP] = p
			allQueries = append(allQueries, QueryItem{Query: qIP})
		}
	}

	var matched []string
	batchSize := 100

	for i := 0; i < len(allQueries); i += batchSize {
		end := i + batchSize
		if end > len(allQueries) {
			end = len(allQueries)
		}
		batch := allQueries[i:end]

		reqBody, _ := json.Marshal(batch)
		resp, err := http.Post("http://ip-api.com/batch?fields=query,countryCode,status", "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			continue
		}

		var resData []struct {
			Query       string `json:"query"`
			CountryCode string `json:"countryCode"`
			Status      string `json:"status"`
		}
		json.NewDecoder(resp.Body).Decode(&resData)
		resp.Body.Close()

		for _, item := range resData {
			if item.Status == "success" && strings.ToUpper(item.CountryCode) == targetCountry {
				if pref, ok := queryToPrefix[item.Query]; ok {
					matched = append(matched, pref)
				}
			}
		}
	}
	return matched
}

// ================= UTILS =================

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func CleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "*.")))
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return ""
	}
	tld := parts[len(parts)-1]
	if bannedTLDs[tld] {
		return ""
	}
	if strings.ContainsAny(d, " \t\r\n/\\:*?\"'<>|#%&={}~`!@$^()+[]") {
		return ""
	}
	if !domainRe.MatchString(d) {
		return ""
	}
	return d
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func classifyDomainQuality(sni string) string {
	sniLower := strings.ToLower(sni)
	for _, tld := range junkTLDs {
		if strings.HasSuffix(sniLower, tld) {
			return "JunkTLD"
		}
	}
	for _, dDNS := range dynDNS {
		if strings.HasSuffix(sniLower, dDNS) {
			return "DynDNS"
		}
	}
	if numRe.MatchString(sniLower) {
		return "Numeric"
	}
	return "Normal"
}

func reverseIPv4(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP")
	}
	parsed = parsed.To4()
	if parsed == nil {
		return "", fmt.Errorf("not IPv4")
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", parsed[3], parsed[2], parsed[1], parsed[0]), nil
}

// ================= ACTIVE RECON (TLS + PTR + OSINT) =================

func getOSINTDomains(ip string) []string {
	var domains []string
	client := &http.Client{Timeout: 4 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/passive_dns", ip), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	if resp, err := client.Do(req); err == nil {
		defer resp.Body.Close()
		var res struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
			for _, r := range res.PassiveDNS {
				if d := CleanDomain(r.Hostname); d != "" {
					domains = append(domains, d)
				}
			}
		}
	}
	return domains
}

func extractDomainsFromTLS(ctx context.Context, ip, sni string, timeout time.Duration) ([]string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	uConn.SetDeadline(time.Now().Add(timeout))
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, nil
	}

	state := uConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil
	}

	var doms []string
	cert := state.PeerCertificates[0]
	for _, d := range cert.DNSNames {
		if cd := CleanDomain(d); cd != "" {
			doms = append(doms, cd)
		}
	}
	if cd := CleanDomain(cert.Subject.CommonName); cd != "" {
		doms = append(doms, cd)
	}

	return uniqueStrings(doms), nil
}

func activeProbeIP(ctx context.Context, ip string, timeout time.Duration, noPTR bool, noTLS bool, pipeStats *PipelineStats) []TargetPair {
	var pairs []TargetPair
	sourceMap := make(map[string]DomainSource)
	var allDoms []string

	addDomain := func(d string, src DomainSource) {
		d = CleanDomain(d)
		if d == "" {
			return
		}
		if _, exists := sourceMap[d]; !exists {
			allDoms = append(allDoms, d)
		}
		sourceMap[d] |= src
	}

	// 1. Direct TLS
	if !noTLS {
		doms, err := extractDomainsFromTLS(ctx, ip, ip, timeout)
		if err != nil {
			return nil // Dead IP, skip
		}
		if len(doms) > 0 {
			pipeStats.mu.Lock()
			pipeStats.IPWithDirectTLS++
			pipeStats.mu.Unlock()

			for _, d := range doms {
				addDomain(d, SourceDirectTLS)
			}

			// Ранний выход как в старой версии
			if len(doms) <= 15 {
				for d, src := range sourceMap {
					pairs = append(pairs, TargetPair{IP: ip, SNI: d, Evidence: src})
				}
				return pairs
			}
		}
	}

	// 2. Нативный быстрый PTR
	if !noPTR {
		pipeStats.mu.Lock()
		pipeStats.PTRQueriesSent++
		pipeStats.mu.Unlock()

		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			pipeStats.mu.Lock()
			pipeStats.PTRFound++
			pipeStats.mu.Unlock()

			for _, name := range names {
				ptrDomain := strings.TrimSuffix(strings.TrimSpace(name), ".")
				ptrDomain = CleanDomain(ptrDomain)
				if ptrDomain != "" {
					addDomain(ptrDomain, SourcePTR)

					if !noTLS {
						cDoms, _ := extractDomainsFromTLS(ctx, ip, ptrDomain, timeout)
						for _, cd := range cDoms {
							addDomain(cd, SourceDirectTLS)
						}
					}
				}
			}
		} else if err != nil {
			pipeStats.mu.Lock()
			pipeStats.PTRErrors++
			pipeStats.mu.Unlock()
		}
	}

	// 3. OSINT
	if len(sourceMap) < 5 {
		osints := getOSINTDomains(ip)
		for _, osint := range osints {
			osint = CleanDomain(osint)
			if osint == "" {
				continue
			}
			addDomain(osint, SourceSeed)

			if !noTLS {
				cDoms, _ := extractDomainsFromTLS(ctx, ip, osint, timeout)
				if len(cDoms) > 0 {
					for _, cd := range cDoms {
						addDomain(cd, SourceDirectTLS)
					}
					break
				}
			}
		}
	}

	for d, src := range sourceMap {
		pairs = append(pairs, TargetPair{IP: ip, SNI: d, Evidence: src})
	}

	sort.Slice(pairs, func(i, j int) bool {
		weight := func(s DomainSource) int {
			w := 0
			if s.Has(SourceDirectTLS) {
				w += 3
			}
			if s.Has(SourcePTR) {
				w += 2
			}
			if s.Has(SourceSeed) {
				w += 1
			}
			return w
		}
		wi, wj := weight(pairs[i].Evidence), weight(pairs[j].Evidence)
		if wi != wj {
			return wi > wj
		}
		return pairs[i].SNI < pairs[j].SNI
	})

	if len(pairs) > 25 {
		pairs = pairs[:25]
	}

	return pairs
}

// ================= RAW DNS + EDNS CLIENT SUBNET =================

// DNSHeader/Question/Answer parsing is intentionally minimal: Stage D only
// needs A records and the DNS response code. We never call net.LookupHost here.

func normalizeDNSResolvers(values []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(v); err == nil {
			v = host
		}
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil {
			continue
		}
		v = ip.To4().String()
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func randomDNSID() uint16 {
	uaMu.Lock()
	defer uaMu.Unlock()
	if uaRng == nil {
		uaRng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return uint16(uaRng.Intn(1 << 16))
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}

	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		if len(out)+1+len(label)+1 > 255 {
			return nil, fmt.Errorf("DNS name too long: %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

// ECS option, RFC 7871:
//
//	OPTION-CODE=8, FAMILY=1 (IPv4), SOURCE PREFIX, SCOPE=0, ADDRESS bytes.
//
// We default to /24 because that is the commonly forwarded IPv4 ECS granularity
// and is also the maximum prefix Google documents for client ECS forwarding.
// The prefix is configurable through -ecs-prefix.
func buildECSOption(clientIP string, prefixLen int) ([]byte, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid ECS IPv4: %q", clientIP)
	}
	if prefixLen < 0 || prefixLen > 32 {
		return nil, fmt.Errorf("invalid ECS IPv4 prefix length: %d", prefixLen)
	}

	ip4 := append([]byte(nil), ip.To4()...)
	usedBytes := (prefixLen + 7) / 8
	if usedBytes > 0 && prefixLen%8 != 0 {
		maskBits := byte(0xFF << uint(8-(prefixLen%8)))
		ip4[usedBytes-1] &= maskBits
	}
	ip4 = ip4[:usedBytes]

	// ECS option payload:
	// FAMILY(2) + SOURCE PREFIX(1) + SCOPE(1) + ADDRESS(variable)
	payloadLen := 4 + len(ip4)
	option := make([]byte, 4+payloadLen)
	binary.BigEndian.PutUint16(option[0:2], 8) // ECS option code
	binary.BigEndian.PutUint16(option[2:4], uint16(payloadLen))
	binary.BigEndian.PutUint16(option[4:6], 1) // IPv4
	option[6] = byte(prefixLen)
	option[7] = 0 // scope prefix
	copy(option[8:], ip4)
	return option, nil
}

func buildDNSQuery(domain string, ecsIP string, ecsPrefix int) ([]byte, uint16, error) {
	name, err := encodeDNSName(domain)
	if err != nil {
		return nil, 0, err
	}
	id := randomDNSID()

	// Header:
	// ID, RD=1, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1 (OPT)
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[10:12], 1)

	// Question: QNAME + QTYPE=A + QCLASS=IN
	buf = append(buf, name...)
	buf = append(buf, 0x00, 0x01, 0x00, 0x01)

	ecs, err := buildECSOption(ecsIP, ecsPrefix)
	if err != nil {
		return nil, 0, err
	}

	// EDNS(0) OPT RR:
	// NAME=0, TYPE=41, UDP payload=1232, EXT-RCODE=0, VERSION=0,
	// FLAGS=0, RDLEN=len(ECS), RDATA=ECS option.
	opt := make([]byte, 11)
	// opt[0] NAME already 0
	binary.BigEndian.PutUint16(opt[1:3], 41)
	binary.BigEndian.PutUint16(opt[3:5], 1232)
	// opt[5] extended RCODE, opt[6] EDNS version, opt[7:9] flags
	binary.BigEndian.PutUint16(opt[9:11], uint16(len(ecs)))
	buf = append(buf, opt...)
	buf = append(buf, ecs...)
	return buf, id, nil
}

func readDNSName(msg []byte, off int) (string, int, error) {
	if off < 0 || off >= len(msg) {
		return "", off, fmt.Errorf("DNS name offset out of bounds")
	}

	var labels []string
	pos := off
	jumped := false
	returnPos := off
	jumps := 0

	for {
		if pos >= len(msg) {
			return "", off, fmt.Errorf("DNS name truncated")
		}
		l := msg[pos]
		if l == 0 {
			pos++
			if !jumped {
				returnPos = pos
			}
			return strings.Join(labels, "."), returnPos, nil
		}

		if l&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", off, fmt.Errorf("DNS compression pointer truncated")
			}
			ptr := int(l&0x3F)<<8 | int(msg[pos+1])
			if ptr >= len(msg) {
				return "", off, fmt.Errorf("DNS compression pointer out of bounds")
			}
			if !jumped {
				returnPos = pos + 2
				jumped = true
			}
			pos = ptr
			jumps++
			if jumps > 32 {
				return "", off, fmt.Errorf("DNS compression loop")
			}
			continue
		}

		if l > 63 {
			return "", off, fmt.Errorf("invalid DNS label length")
		}
		pos++
		if pos+int(l) > len(msg) {
			return "", off, fmt.Errorf("DNS label truncated")
		}
		labels = append(labels, string(msg[pos:pos+int(l)]))
		pos += int(l)
		if !jumped {
			returnPos = pos
		}
	}
}

func parseDNSAResponse(msg []byte, wantID uint16) ([]string, int, error) {
	if len(msg) < 12 {
		return nil, 0, fmt.Errorf("short DNS response")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if id != wantID {
		return nil, 0, fmt.Errorf("DNS transaction ID mismatch")
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, 0, fmt.Errorf("not a DNS response")
	}
	rcode := int(flags & 0x000F)

	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))

	// DNS RCODE 3 = NXDOMAIN. Returning ErrDNSNXDomain allows the Stage D
	// telemetry/cache behavior to remain unchanged.
	if rcode == 3 {
		return nil, rcode, ErrDNSNXDomain
	}
	if rcode != 0 {
		return nil, rcode, fmt.Errorf("DNS server returned RCODE=%d", rcode)
	}

	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readDNSName(msg, off)
		if err != nil {
			return nil, rcode, err
		}
		off = next
		if off+4 > len(msg) {
			return nil, rcode, fmt.Errorf("truncated DNS question")
		}
		off += 4
	}

	var ips []string
	parseRR := func() error {
		_, next, err := readDNSName(msg, off)
		if err != nil {
			return err
		}
		off = next
		if off+10 > len(msg) {
			return fmt.Errorf("truncated DNS RR header")
		}

		qtype := binary.BigEndian.Uint16(msg[off : off+2])
		qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return fmt.Errorf("truncated DNS RDATA")
		}

		if qtype == 1 && qclass == 1 && rdlen == 4 {
			ip := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3]).String()
			ips = append(ips, ip)
		}
		off += rdlen
		return nil
	}

	for i := 0; i < an+ns+ar; i++ {
		if err := parseRR(); err != nil {
			return nil, rcode, err
		}
	}

	return uniqueStrings(ips), rcode, nil
}

func dnsExchangeUDP(ctx context.Context, resolver, domain, ecsIP string, ecsPrefix int, timeout time.Duration) ([]string, error) {
	query, id, err := buildDNSQuery(domain, ecsIP, ecsPrefix)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(resolver, "53")
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	ips, _, parseErr := parseDNSAResponse(buf[:n], id)
	return ips, parseErr
}

func (r *RuntimeCaches) claimDNSTrace(domain string, limit int) bool {
	if limit == 0 {
		return false
	}
	r.DNSTraceMu.Lock()
	defer r.DNSTraceMu.Unlock()
	if r.DNSTraceSeen == nil {
		r.DNSTraceSeen = make(map[string]struct{})
	}
	if _, ok := r.DNSTraceSeen[domain]; ok {
		return false
	}
	if limit > 0 && r.DNSTracePrinted >= limit {
		return false
	}
	r.DNSTraceSeen[domain] = struct{}{}
	r.DNSTracePrinted++
	return true
}

type dnsTraceResult struct {
	resolver string
	ips      []string
	err      error
}

func resolveHostECSAllResolvers(ctx context.Context, domain, ecsIP string, ecsPrefix int, resolvers []string, timeout time.Duration, rtCaches *RuntimeCaches) ([]string, error) {
	results := make(chan dnsTraceResult, len(resolvers))
	var wg sync.WaitGroup

	for _, resolver := range resolvers {
		resolver := resolver
		wg.Add(1)
		go func() {
			defer wg.Done()
			stat := rtCaches.dnsResolverStat(resolver)
			rtCaches.DNSStatsMu.Lock()
			stat.Attempts++
			rtCaches.DNSStatsMu.Unlock()

			ips, err := dnsExchangeUDP(ctx, resolver, domain, ecsIP, ecsPrefix, timeout)

			rtCaches.DNSStatsMu.Lock()
			if err == nil {
				stat.Answers++
				stat.IPv4s += len(ips)
			} else if errors.Is(err, ErrDNSNXDomain) {
				stat.NXDomain++
			} else {
				stat.Failures++
				if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
					stat.Timeouts++
				}
			}
			rtCaches.DNSStatsMu.Unlock()

			results <- dnsTraceResult{resolver: resolver, ips: ips, err: err}
		}()
	}

	wg.Wait()
	close(results)

	all := make([]dnsTraceResult, 0, len(resolvers))
	resultByResolver := make(map[string]dnsTraceResult, len(resolvers))
	var firstErr error
	for r := range results {
		all = append(all, r)
		resultByResolver[r.resolver] = r
		if firstErr == nil && r.err != nil {
			firstErr = r.err
		}
	}

	// Keep the normal resolver-pool ordering semantics even though trace mode
	// sends the diagnostic queries concurrently.
	var winner []string
	for _, resolver := range resolvers {
		if r, ok := resultByResolver[resolver]; ok && r.err == nil && len(r.ips) > 0 {
			winner = append([]string(nil), r.ips...)
			break
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].resolver < all[j].resolver })
	fmt.Printf("[DNS-TRACE] %s (ECS %s/%d)\n", domain, ecsIP, ecsPrefix)
	for _, r := range all {
		switch {
		case r.err == nil:
			ans := "NO-IPv4"
			if len(r.ips) > 0 {
				ans = strings.Join(r.ips, ", ")
			}
			fmt.Printf("    %-15s -> %s\n", r.resolver, ans)
		case errors.Is(r.err, ErrDNSNXDomain):
			fmt.Printf("    %-15s -> NXDOMAIN\n", r.resolver)
		default:
			fmt.Printf("    %-15s -> ERR: %v\n", r.resolver, r.err)
		}
	}

	if len(winner) > 0 {
		return winner, nil
	}
	if errors.Is(firstErr, ErrDNSNXDomain) {
		return nil, ErrDNSNXDomain
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("all DNS resolvers returned no IPv4")
	}
	return nil, firstErr
}

func resolveHostECS(ctx context.Context, domain, ecsIP string, ecsPrefix int, resolvers []string, timeout time.Duration, rtCaches *RuntimeCaches) ([]string, error) {
	domain = CleanDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("invalid domain")
	}
	if ecsIP == "" {
		return nil, fmt.Errorf("ECS client IP is empty")
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("DNS resolver pool is empty")
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	// Query the pool sequentially so a single broken/filtered resolver does not
	// block the whole validation stage. A successful answer wins immediately.
	var lastErr error
	start := randomDNSID()
	for i := 0; i < len(resolvers); i++ {
		// Rotate the pool per logical lookup for distribution.
		idx := (int(start) + i) % len(resolvers)
		resolver := resolvers[idx]
		stat := rtCaches.dnsResolverStat(resolver)
		rtCaches.DNSStatsMu.Lock()
		stat.Attempts++
		rtCaches.DNSStatsMu.Unlock()

		ips, err := dnsExchangeUDP(ctx, resolver, domain, ecsIP, ecsPrefix, timeout)
		if err == nil {
			rtCaches.DNSStatsMu.Lock()
			stat.Answers++
			stat.IPv4s += len(ips)
			rtCaches.DNSStatsMu.Unlock()
			return ips, nil
		}
		if errors.Is(err, ErrDNSNXDomain) {
			rtCaches.DNSStatsMu.Lock()
			stat.NXDomain++
			rtCaches.DNSStatsMu.Unlock()
			return nil, ErrDNSNXDomain
		}
		rtCaches.DNSStatsMu.Lock()
		stat.Failures++
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			stat.Timeouts++
		}
		rtCaches.DNSStatsMu.Unlock()
		lastErr = fmt.Errorf("%s: %w", resolver, err)

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all DNS resolvers failed")
	}
	return nil, lastErr
}

func resolveHostCached(ctx context.Context, domain string, rtCaches *RuntimeCaches, cfg Config) ([]string, error) {
	domain = CleanDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("invalid domain")
	}

	// Cache includes the ECS client prefix. In the current scanner the ECS IP is
	// the VPS public IP, so a single RunPipeline has a stable cache context.
	cacheKey := fmt.Sprintf("%s|ecs=%s/%d|dns=%s",
		domain, cfg.ECSIP, cfg.ECSPrefix, strings.Join(cfg.DNSResolvers, ","))

	v, err, _ := rtCaches.DNSGroup.Do(cacheKey, func() (interface{}, error) {
		if cached, ok := rtCaches.DNSCache.Get(cacheKey); ok {
			if cached.NXDomain {
				return nil, ErrDNSNXDomain
			}
			return cached.IPs, nil
		}

		var ips []string
		var err error
		traceThisDomain := cfg.DNSTrace && rtCaches.claimDNSTrace(domain, cfg.DNSTraceLimit)
		if traceThisDomain {
			ips, err = resolveHostECSAllResolvers(
				ctx, domain, cfg.ECSIP, cfg.ECSPrefix, cfg.DNSResolvers,
				time.Duration(cfg.DNSQueryTimeoutMs)*time.Millisecond, rtCaches,
			)
		} else {
			ips, err = resolveHostECS(
				ctx, domain, cfg.ECSIP, cfg.ECSPrefix, cfg.DNSResolvers,
				time.Duration(cfg.DNSQueryTimeoutMs)*time.Millisecond, rtCaches,
			)
		}
		if err != nil {
			if errors.Is(err, ErrDNSNXDomain) {
				rtCaches.DNSCache.Put(cacheKey, &DNSCacheEntry{NXDomain: true}, 10*time.Second)
			}
			return nil, err
		}

		var validIPs []string
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				validIPs = append(validIPs, ip)
			}
		}

		rtCaches.DNSCache.Put(cacheKey, &DNSCacheEntry{IPs: validIPs}, 10*time.Second)
		return validIPs, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

// ================= CIDR & SAMPLING =================
type ipRange struct{ start, end uint64 }

func MergeCIDRs(cidrs []string) []ipRange {
	var ranges []ipRange
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil || ipnet.Mask == nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		var count uint64
		if ones == 0 {
			count = 1 << 32
		} else {
			count = uint64(1) << uint(32-ones)
		}
		startInt := uint64(binary.BigEndian.Uint32(ipnet.IP))
		ranges = append(ranges, ipRange{startInt, startInt + count - 1})
	}
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	var merged []ipRange
	for _, r := range ranges {
		if len(merged) == 0 {
			merged = append(merged, r)
			continue
		}
		last := &merged[len(merged)-1]
		if r.start <= last.end+1 {
			if r.end > last.end {
				last.end = r.end
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func generateIPs(cidrs []string, maxIPs int) []string {
	var ips []string
	seen := make(map[string]bool)

	for _, pStr := range cidrs {
		if maxIPs > 0 && len(ips) >= maxIPs {
			break
		}
		ip, ipnet, err := net.ParseCIDR(pStr)
		if err != nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		limit := MaxHostsPer24
		if ones < 24 {
			limit = MaxHostsPer24 * MaxSampled24
		}

		count := 0
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ipStr := ip.String()
			if !seen[ipStr] && !strings.HasSuffix(ipStr, ".0") && !strings.HasSuffix(ipStr, ".255") {
				seen[ipStr] = true
				ips = append(ips, ipStr)
				count++
				if maxIPs > 0 && len(ips) >= maxIPs {
					return ips
				}
				if count >= limit {
					break
				}
			}
		}
	}
	return ips
}

func ipInRanges(ipStr string, ranges []ipRange) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return false
	}
	val := uint64(binary.BigEndian.Uint32(ip4))
	for _, r := range ranges {
		if val >= r.start && val <= r.end {
			return true
		}
	}
	return false
}

// ================= HTTP/2 PROBE =================
const clientAdvertisedMaxFrameSize = 16384

type ProbeStage int

const (
	ProbeStageTCP ProbeStage = iota
	ProbeStageTLS
	ProbeStageTLSValidation
	ProbeStageH2
	ProbeStageHeaders
	ProbeStageComplete
)

type ProbeError struct {
	Stage ProbeStage
	Err   error
}

func (e *ProbeError) Error() string { return e.Err.Error() }

func writeH2(conn net.Conn, b []byte, timeout time.Duration) error {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	n, err := conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("short write")
	}
	return nil
}

func buildH2HeadersEncoder(sni string) []byte {
	var payload []byte
	payload = append(payload, 0x82, 0x87, 0x84)
	sniBytes := []byte(sni)
	payload = append(payload, 0x01, byte(len(sniBytes)))
	payload = append(payload, sniBytes...)
	ua := []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")
	payload = append(payload, 0x0F, 0x2B, byte(len(ua)))
	payload = append(payload, ua...)
	return payload
}

func buildH2Frame(frameType, flags byte, streamId uint32, payload []byte) []byte {
	length := len(payload)
	header := make([]byte, 9)
	header[0], header[1], header[2] = byte(length>>16), byte(length>>8), byte(length)
	header[3], header[4] = frameType, flags
	binary.BigEndian.PutUint32(header[5:9], streamId&0x7FFFFFFF)
	return append(header, payload...)
}

func buildWindowUpdateFrame(streamID uint32, increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment&0x7FFFFFFF)
	return buildH2Frame(FrameWindowUpdate, 0, streamID, payload)
}

func parseResponseHeaders(cand *Candidate, headers []hpack.HeaderField) {
	weakCount := 0
	hasStatus := false

	for _, h := range headers {
		hName := strings.ToLower(strings.TrimSpace(h.Name))

		if hName == ":status" {
			if n, err := strconv.Atoi(strings.TrimSpace(h.Value)); err == nil && n > 0 {
				cand.HTTPStatus = n
			}
			hasStatus = true
			continue
		}

		hValLower := strings.ToLower(h.Value)
		switch hName {
		case "server":
			cand.Server = h.Value
			for _, cdn := range cdnStrong {
				if strings.Contains(hValLower, cdn) {
					cand.CDNStatus = CDNConfirmed
					cand.CDNProvider = cdn
				}
			}
		case "content-type":
			cand.ContentType = h.Value
		case "location":
			cand.Location = h.Value
		case "cf-ray":
			cand.CDNStatus = CDNConfirmed
			cand.CDNProvider = "cloudflare"
		}

		if strings.HasPrefix(hName, "x-amz-cf-") ||
			strings.HasPrefix(hName, "x-sucuri-") ||
			strings.HasPrefix(hName, "x-akamai-") {
			cand.CDNStatus = CDNConfirmed
			if cand.CDNProvider == "" {
				cand.CDNProvider = "headers"
			}
		}

		for _, cdnH := range cdnWeak {
			if hName == cdnH {
				weakCount++
			}
		}
	}

	if !hasStatus {
		cand.MissingStatus = true
	}

	if cand.CDNStatus == CDNStatusUnknown && weakCount > 0 {
		cand.CDNStatus = CDNLikely
	}

	cand.ResponseHeadersParsed = true
}

func parseTrailers(cand *Candidate, headers []hpack.HeaderField) {
	cand.ResponseTrailersSeen = true
}

func ProbeH2(ctx context.Context, ip, sni string, ev DomainSource, cfg Config) (*Candidate, *ProbeError) {
	cand := &Candidate{
		IP:            ip,
		SNI:           sni,
		Evidence:      ev,
		DomainQuality: classifyDomainQuality(sni),
		CDNStatus:     CDNStatusUnknown,
		HTTPStatus:    0,
	}

	t0 := time.Now()
	dialer := &net.Dialer{Timeout: time.Duration(cfg.TCPTimeoutMs) * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return cand, &ProbeError{Stage: ProbeStageTCP, Err: err}
	}
	defer conn.Close()
	cand.Timings.TCP = time.Since(t0)

	t1 := time.Now()
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}, utls.HelloChrome_Auto)

	uConn.SetDeadline(time.Now().Add(time.Duration(cfg.TLSTimeoutMs) * time.Millisecond))
	if err := uConn.HandshakeContext(ctx); err != nil {
		return cand, &ProbeError{Stage: ProbeStageTLS, Err: err}
	}
	cand.Timings.TLS = time.Since(t1)
	uConn.SetDeadline(time.Time{})

	state := uConn.ConnectionState()

	if state.Version != tls.VersionTLS13 {
		return cand, &ProbeError{
			Stage: ProbeStageTLS,
			Err:   fmt.Errorf("unexpected TLS version: 0x%x", state.Version),
		}
	}
	cand.TLS13 = true

	if state.NegotiatedProtocol == "h2" {
		cand.ALPN = "h2"
	} else {
		cand.ALPN = "h2 (no ALPN)"
	}

	if len(state.PeerCertificates) == 0 {
		return cand, &ProbeError{Stage: ProbeStageTLSValidation, Err: fmt.Errorf("no peer certificates provided")}
	}

	cert := state.PeerCertificates[0]
	cand.CertIssuer = cert.Issuer.CommonName
	if cand.CertIssuer == "" && len(cert.Issuer.Organization) > 0 {
		cand.CertIssuer = cert.Issuer.Organization[0]
	}
	cand.CertSubject = cert.Subject.CommonName
	cand.CertSANCount = len(cert.DNSNames) + len(cert.IPAddresses)

	now := time.Now()
	cand.CertValidTime = now.After(cert.NotBefore) && now.Before(cert.NotAfter)

	opts := x509.VerifyOptions{
		DNSName:       sni,
		Roots:         nil,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}

	if _, err := cert.Verify(opts); err == nil {
		cand.CertSNIMatch = true
		cand.CertChainValid = true
	} else {
		cand.CertChainValid = false
		cand.CertSNIMatch = (cert.VerifyHostname(sni) == nil)
	}

	wTo := time.Duration(cfg.H2WriteTimeoutMs) * time.Millisecond

	if err := writeH2(uConn, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), wTo); err != nil {
		return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
	}
	if err := writeH2(uConn, buildH2Frame(FrameSettings, 0, 0, nil), wTo); err != nil {
		return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
	}
	if err := writeH2(uConn, buildH2Frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, buildH2HeadersEncoder(sni)), wTo); err != nil {
		return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
	}

	requestSent := time.Now()
	uConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.H2ReadTimeoutMs) * time.Millisecond))

	const maxInboundFrameSize = uint32(clientAdvertisedMaxFrameSize)
	buf := make([]byte, 32768)
	recvBuf := bytes.Buffer{}
	headerBlocks := bytes.Buffer{}
	decoder := hpack.NewDecoder(4096, nil)

	firstFrameSeen := false
	var expectingContinuation bool
	var activeStreamID uint32

ReadLoop:
	for {
		if ctx.Err() != nil {
			break ReadLoop
		}
		n, err := uConn.Read(buf)
		if n > 0 {
			recvBuf.Write(buf[:n])
		}

		for recvBuf.Len() >= 9 {
			data := recvBuf.Bytes()
			length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
			if length > maxInboundFrameSize {
				break ReadLoop
			}
			if uint32(recvBuf.Len()) < 9+length {
				break
			}
			if !firstFrameSeen {
				cand.Timings.H2FirstFrame = time.Since(requestSent)
				firstFrameSeen = true
			}

			frameType, flags := data[3], data[4]
			streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF
			payload := data[9 : 9+length]
			recvBuf.Next(int(9 + length))

			if frameType == FrameSettings || frameType == FrameHeaders || frameType == FrameData || frameType == FrameWindowUpdate || frameType == FrameGoAway {
				cand.H2ProtocolConfirmed = true
			}

			if expectingContinuation && frameType != FrameContinuation {
				continue
			}

			switch frameType {
			case FrameSettings:
				if length%6 != 0 {
					continue
				}
				if flags&FlagAck != 0 {
					cand.H2SettingsAckReceived = true
					cand.SettingsAckCount++
					break
				}
				cand.SettingsFramesCount++
				var prof PeerSettingsProfile
				if cand.H2SettingsReceived {
					prof = cand.LatestPeerSettings
				}
				for i := 0; i+6 <= int(length); i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					switch id {
					case 1:
						prof.HeaderTableSize = val
						prof.HasHeaderTableSize = true
						decoder.SetMaxDynamicTableSize(val)
					case 3:
						prof.MaxConcurrentStreams = val
						prof.HasMaxConcurrentStreams = true
					case 4:
						prof.InitialWindowSize = val
						prof.HasInitialWindowSize = true
					case 5:
						prof.MaxFrameSize = val
						prof.HasMaxFrameSize = true
					case 6:
						prof.MaxHeaderListSize = val
						prof.HasMaxHeaderListSize = true
					}
				}
				if !cand.H2SettingsReceived {
					cand.InitialPeerSettings = prof
					cand.LatestPeerSettings = prof
					cand.H2SettingsReceived = true
				} else {
					if prof != cand.LatestPeerSettings {
						cand.SettingsChanges++
					}
					cand.LatestPeerSettings = prof
				}
				_ = writeH2(uConn, buildH2Frame(FrameSettings, FlagAck, 0, nil), wTo)
				cand.H2SettingsAckSent = true

			case FrameHeaders:
				if streamID == 1 {
					isTrailers := cand.EndStreamSeen
					if (flags & FlagEndStream) != 0 {
						cand.EndStreamSeen = true
					}
					actualPayload := payload
					padLen := 0
					if flags&FlagPadded != 0 && len(actualPayload) > 0 {
						padLen = int(actualPayload[0])
						actualPayload = actualPayload[1:]
					}
					if flags&FlagPriority != 0 && len(actualPayload) >= 5 {
						actualPayload = actualPayload[5:]
					}
					if padLen > len(actualPayload) {
						padLen = len(actualPayload)
					}
					actualPayload = actualPayload[:len(actualPayload)-padLen]

					headerBlocks.Write(actualPayload)
					if (flags & FlagEndHeaders) == 0 {
						expectingContinuation = true
						activeStreamID = streamID
					} else {
						expectingContinuation = false
						headers, errDecode := decoder.DecodeFull(headerBlocks.Bytes())
						if errDecode != nil {
							cand.HPACKErrors = true
						}

						if !cand.ResponseHeadersParsed && !isTrailers {
							parseResponseHeaders(cand, headers)
							headerBlocks.Reset()

							cand.Timings.H2Headers = time.Since(requestSent)
							cand.H2HeadersReceived = true

							break ReadLoop
						} else if isTrailers {
							parseTrailers(cand, headers)
						}
						headerBlocks.Reset()
					}
				}
			case FrameContinuation:
				if !expectingContinuation || streamID != activeStreamID {
					continue
				}
				headerBlocks.Write(payload)
				if (flags & FlagEndHeaders) != 0 {
					expectingContinuation = false
					headers, errDecode := decoder.DecodeFull(headerBlocks.Bytes())
					if errDecode != nil {
						cand.HPACKErrors = true
					}

					if !cand.ResponseHeadersParsed {
						parseResponseHeaders(cand, headers)
						headerBlocks.Reset()

						cand.Timings.H2Headers = time.Since(requestSent)
						cand.H2HeadersReceived = true

						break ReadLoop
					} else {
						parseTrailers(cand, headers)
					}
					headerBlocks.Reset()
				}
			case FrameData:
				if streamID == 1 {
					cand.H2DataFrames++
					if (flags & FlagEndStream) != 0 {
						cand.EndStreamSeen = true
					}
					actualPayload := payload
					padLen := 0
					if flags&FlagPadded != 0 && len(actualPayload) > 0 {
						padLen = int(actualPayload[0])
						actualPayload = actualPayload[1:]
					}
					if padLen > len(actualPayload) {
						padLen = len(actualPayload)
					}
					actualPayload = actualPayload[:len(actualPayload)-padLen]

					cand.BodyBytes += len(actualPayload)
					inc := length
					if inc > 0 {
						_ = writeH2(uConn, buildWindowUpdateFrame(1, inc), wTo)
						_ = writeH2(uConn, buildWindowUpdateFrame(0, inc), wTo)
					}
				}
			case FrameRSTStream:
				if streamID == 1 {
					cand.StreamReset = true
					break ReadLoop
				}
			case FrameGoAway:
				cand.GoAwaySeen = true
			}

			if cand.H2ProtocolConfirmed && cand.H2HeadersReceived && (cand.BodyBytes > 0 || cand.Server != "" || cand.EndStreamSeen) {
				break ReadLoop
			}
		}

		if err != nil {
			if cand.H2ProtocolConfirmed {
				cand.ReadTimeout = true
				break ReadLoop
			}
			return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
		}
	}

	if !cand.H2ProtocolConfirmed {
		return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("no valid H2 frames received")}
	}

	return cand, nil
}

// ================= SCORING & ENRICHMENT =================

func scoreH2Profile(c *Candidate) float64 {
	score := 0.0
	if c.H2SettingsReceived {
		score += 5.0
	}
	prof := c.InitialPeerSettings
	if prof.HasMaxConcurrentStreams && prof.MaxConcurrentStreams > 0 && prof.MaxConcurrentStreams <= 1000 {
		score += 3.0
	}
	if prof.HasInitialWindowSize {
		switch {
		case prof.InitialWindowSize == 65535:
			score += 1.0
		case prof.InitialWindowSize > 65535:
			score += 3.0
		}
	}
	if prof.HasMaxFrameSize {
		switch {
		case prof.MaxFrameSize == 16384:
			score += 1.0
		case prof.MaxFrameSize > 16384:
			score += 3.0
		}
	}
	if c.H2DataFrames > 0 {
		score += 3.0
	}
	if c.BodyBytes >= 1024 {
		score += 1.0
	}
	if c.EndStreamSeen {
		score += 2.0
	}
	return math.Min(score, 20.0)
}

func validateAndEnrich(cand *Candidate, cfg Config, pipeStats *PipelineStats) bool {
	if !cand.H2ProtocolConfirmed {
		return false
	}
	if !cand.H2HeadersReceived {
		return false
	}
	if cand.MissingStatus || cand.HTTPStatus <= 0 {
		return false
	}

	rs := RealityScore{}

	if cand.TLS13 {
		rs.TLSQuality += 10.0
	}
	if cand.ALPN == "h2" {
		rs.TLSQuality += 10.0
	}

	if cand.CertValidTime {
		rs.Certificate += 5.0
	}
	if cand.CertSNIMatch {
		rs.Certificate += 10.0
	}
	if cand.CertChainValid {
		rs.Certificate += 5.0
	}

	rs.H2Profile = scoreH2Profile(cand)

	if cand.Server != "" && cand.Server != "-" {
		srvLower := strings.ToLower(cand.Server)
		if strings.Contains(srvLower, "nginx") || strings.Contains(srvLower, "caddy") || strings.Contains(srvLower, "apache") || strings.Contains(srvLower, "openresty") {
			rs.ServerProfile = 10
		} else {
			rs.ServerProfile = 6
		}
	} else {
		rs.ServerProfile = 3
	}

	switch cand.HTTPStatus {
	case 200:
		rs.HTTPBehavior = 10
	case 301, 302, 307, 308:
		rs.HTTPBehavior = 7
	default:
		if cand.HTTPStatus >= 400 && cand.HTTPStatus < 500 {
			rs.HTTPBehavior = 5
		} else if cand.HTTPStatus >= 500 {
			rs.HTTPBehavior = -5
		}
	}

	discovery := 0.0
	scoreDirect := func(src DomainSource, pts float64) {
		if cand.Evidence.Has(src) {
			discovery += pts
		}
	}
	scoreDirect(SourcePTR, 3.0)
	scoreDirect(SourceDirectTLS, 4.0)
	scoreDirect(SourceSeed, 1.0)

	diversity := 0
	if cand.Evidence.Has(SourcePTR) {
		diversity++
	}
	if cand.Evidence.Has(SourceDirectTLS) {
		diversity++
	}
	if cand.Evidence.Has(SourceSeed) {
		diversity++
	}
	if diversity >= 2 {
		discovery += 2.0
	}
	if diversity >= 3 {
		discovery += 2.0
	}
	rs.DiscoveryScore = math.Min(discovery, 10.0)

	rtt := cand.Timings.TotalProbeLatency().Milliseconds()
	if rtt <= 50 {
		rs.Latency = 10
	} else if rtt <= 150 {
		rs.Latency = 7
	} else if rtt <= 300 {
		rs.Latency = 4
	} else {
		rs.Latency = 1
	}

	rs.Total = rs.TLSQuality + rs.Certificate + rs.H2Profile + rs.ServerProfile + rs.HTTPBehavior + rs.DiscoveryScore + rs.Latency

	scorePenalty := 0.0
	switch cand.DomainQuality {
	case "Numeric":
		scorePenalty = 30.0
	case "DynDNS":
		scorePenalty = 20.0
	case "JunkTLD":
		scorePenalty = 5.0
	}
	if cand.CDNStatus == CDNLikely {
		scorePenalty += 10.0
	}

	cand.RealityScore = rs
	cand.DomainPenalty = scorePenalty
	cand.Score = rs.Total - scorePenalty

	return true
}

func limitStr(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func RunPipeline(ctx context.Context, cfg Config, sampledIPs []string, scanRanges []ipRange) []Candidate {
	pipeStats := NewPipelineStats()
	pipeStats.mu.Lock()
	pipeStats.IPSampled = len(sampledIPs)
	pipeStats.mu.Unlock()

	rtCaches := NewRuntimeCaches()

	var allPairs []TargetPair
	var pairsMu sync.Mutex

	fmt.Printf("[*] STAGE A: Active Discovery (PTR & Direct TLS & OSINT)...\n")
	gA, gCtxA := errgroup.WithContext(ctx)
	gA.SetLimit(cfg.Workers)

	for _, ip := range sampledIPs {
		ip := ip
		gA.Go(func() error {
			if gCtxA.Err() != nil {
				return gCtxA.Err()
			}
			pipeStats.mu.Lock()
			pipeStats.ActiveProbes++
			pipeStats.mu.Unlock()

			pairs := activeProbeIP(gCtxA, ip, time.Duration(cfg.TLSTimeoutMs)*time.Millisecond, cfg.NoPTR, cfg.NoActiveTLS, pipeStats)
			if len(pairs) > 0 {
				pairsMu.Lock()
				allPairs = append(allPairs, pairs...)
				pairsMu.Unlock()
			}
			return nil
		})
	}
	if err := gA.Wait(); err != nil || ctx.Err() != nil {
		fmt.Println("[-] Выполнение прервано (Stage A).")
		return nil
	}

	for _, d := range cfg.Domains {
		if cleaned := CleanDomain(d); cleaned != "" {
			pairsMu.Lock()
			if len(sampledIPs) > 0 {
				allPairs = append(allPairs, TargetPair{IP: sampledIPs[0], SNI: cleaned, Evidence: SourceSeed})
			}
			pairsMu.Unlock()
		}
	}

	uniqueDomsD := make(map[string]bool)
	for _, p := range allPairs {
		uniqueDomsD[p.SNI] = true
	}
	pipeStats.mu.Lock()
	pipeStats.UniqueDomains = len(uniqueDomsD)
	pipeStats.mu.Unlock()

	fmt.Printf("[+] Этап A завершен. Найдено уникальных доменов: %d (Пар IP+SNI: %d)\n", len(uniqueDomsD), len(allPairs))
	if len(allPairs) == 0 {
		return nil
	}

	var validPairs []TargetPair

	if cfg.Mode == ModeDirect && cfg.DirectSNI != "" {
		sni := CleanDomain(cfg.DirectSNI)
		if sni != "" {
			for _, ip := range sampledIPs {
				validPairs = append(validPairs, TargetPair{
					IP:       ip,
					SNI:      sni,
					Evidence: SourceSeed,
				})
			}
		}
	}

	fmt.Printf("[*] STAGE D: DNS Validation (%d Pairs)...\n", len(allPairs))
	var uniqueResolvedIPs sync.Map
	var uniqueTargetIPs sync.Map
	var pairSeen sync.Map

	jobs := make(chan TargetPair, len(allPairs))
	for _, p := range allPairs {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < cfg.DNSWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					return
				}

				pipeStats.mu.Lock()
				pipeStats.DNSQueries++
				pipeStats.mu.Unlock()

				ips, err := resolveHostCached(ctx, p.SNI, rtCaches, cfg)

				pipeStats.mu.Lock()
				if err != nil {
					if errors.Is(err, ErrDNSNXDomain) {
						pipeStats.DNSSuccess++
						pipeStats.DNSNXDomain++
					} else {
						pipeStats.DNSFailed++
						var dnsErr *net.DNSError
						if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
							pipeStats.DNSTimeout++
						} else if errors.As(err, &dnsErr) {
							if dnsErr.Timeout() {
								pipeStats.DNSTimeout++
							} else if dnsErr.Temporary() {
								pipeStats.DNSTemporary++
							} else {
								pipeStats.DNSOtherErr++
							}
						} else {
							pipeStats.DNSOtherErr++
						}
					}
					pipeStats.mu.Unlock()
					continue
				}

				if len(ips) == 0 {
					pipeStats.DNSSuccess++
					pipeStats.DNSNoIPv4++
					pipeStats.mu.Unlock()
					continue
				}

				pipeStats.DNSSuccess++
				pipeStats.DNSResolvedIPs += len(ips)
				pipeStats.mu.Unlock()

				matched := false
				for _, resolvedIP := range ips {
					uniqueResolvedIPs.Store(resolvedIP, struct{}{})

					if resolvedIP == p.IP || ipInRanges(resolvedIP, scanRanges) {
						uniqueTargetIPs.Store(resolvedIP, struct{}{})
						matched = true

						pipeStats.mu.Lock()
						pipeStats.DNSTargetRangeMatches++
						pipeStats.mu.Unlock()

						pairKey := resolvedIP + "\x00" + p.SNI
						if _, loaded := pairSeen.LoadOrStore(pairKey, true); !loaded {
							pairsMu.Lock()
							if len(validPairs) < LimitValidPairs {
								validPairs = append(validPairs, TargetPair{
									IP:       resolvedIP,
									SNI:      p.SNI,
									Evidence: p.Evidence,
								})
							}
							pairsMu.Unlock()
						}
						break
					}
				}
				if matched {
					pipeStats.mu.Lock()
					pipeStats.DNSTargetDomains++
					pipeStats.mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		fmt.Println("[-] Выполнение прервано (Stage D).")
		return nil
	}

	uniqueResolvedCount := 0
	uniqueResolvedIPs.Range(func(k, v interface{}) bool {
		uniqueResolvedCount++
		return true
	})
	uniqueTargetCount := 0
	uniqueTargetIPs.Range(func(k, v interface{}) bool {
		uniqueTargetCount++
		return true
	})

	pipeStats.mu.Lock()
	pipeStats.DNSUniqueResolvedIPs = uniqueResolvedCount
	pipeStats.DNSUniqueTargetIPs = uniqueTargetCount
	pipeStats.DNSValidPairs = len(validPairs)

	fmt.Printf("[+] Stage D Завершён.\n")
	fmt.Printf("    - DNS Queries: %d (Success: %d, Failed: %d)\n", pipeStats.DNSQueries, pipeStats.DNSSuccess, pipeStats.DNSFailed)
	fmt.Printf("    - NXDOMAIN: %d, Timeout: %d, OtherErr: %d, NoIPv4: %d\n", pipeStats.DNSNXDomain, pipeStats.DNSTimeout, pipeStats.DNSOtherErr, pipeStats.DNSNoIPv4)
	fmt.Printf("    - Подтверждено DNS-пар (IP+SNI): %d\n", pipeStats.DNSValidPairs)
	pipeStats.mu.Unlock()

	if len(validPairs) == 0 {
		return nil
	}

	fmt.Printf("[*] STAGE E: Active HTTP/2 Scanning & TLS Enrichment (%d targets)...\n", len(validPairs))
	var candidates []Candidate
	var candMu sync.Mutex

	h2jobs := make(chan TargetPair, len(validPairs))
	var wgE sync.WaitGroup

	tcpTimeout := time.Duration(cfg.TCPTimeoutMs) * time.Millisecond
	if tcpTimeout < 3000*time.Millisecond {
		tcpTimeout = 3000 * time.Millisecond
	}
	cfg.TCPTimeoutMs = int(tcpTimeout.Milliseconds())

	tlsTimeout := time.Duration(cfg.TLSTimeoutMs) * time.Millisecond
	if tlsTimeout < 3000*time.Millisecond {
		tlsTimeout = 3000 * time.Millisecond
	}
	cfg.TLSTimeoutMs = int(tlsTimeout.Milliseconds())

	for i := 0; i < cfg.Workers; i++ {
		wgE.Add(1)
		go func() {
			defer wgE.Done()
			for p := range h2jobs {
				if ctx.Err() != nil {
					return
				}

				cand, pErr := ProbeH2(ctx, p.IP, p.SNI, p.Evidence, cfg)

				pipeStats.mu.Lock()

				// 1. TCP
				if pErr != nil && pErr.Stage == ProbeStageTCP {
					errStr := pErr.Err.Error()
					if os.IsTimeout(pErr.Err) || strings.Contains(errStr, "deadline") || strings.Contains(errStr, "i/o timeout") {
						pipeStats.TCPTimeouts++
					} else if strings.Contains(errStr, "refused") {
						pipeStats.TCPRefused++
					} else {
						pipeStats.TCPOtherErrs++
					}
					pipeStats.mu.Unlock()
					continue
				}
				pipeStats.TCPConnected++

				// 2. TLS
				if pErr != nil && (pErr.Stage == ProbeStageTLS || pErr.Stage == ProbeStageTLSValidation) {
					errStr := pErr.Err.Error()
					if os.IsTimeout(pErr.Err) || strings.Contains(errStr, "deadline") || strings.Contains(errStr, "i/o timeout") {
						pipeStats.TLSTimeouts++
					} else if strings.Contains(errStr, "no peer certificates") {
						pipeStats.NoPeerCertificates++
					} else if strings.Contains(errStr, "handshake failure") {
						pipeStats.TLSHandshakeFailure++
					} else if strings.Contains(errStr, "unrecognized name") {
						pipeStats.TLSUnrecognizedName++
					} else if strings.Contains(errStr, "connection reset") {
						pipeStats.TLSConnectionReset++
					} else if errors.Is(pErr.Err, io.EOF) || strings.Contains(errStr, "EOF") {
						pipeStats.TLSEOF++
					} else if pErr.Stage == ProbeStageTLSValidation {
						pipeStats.TLSValidationFailures++
					} else {
						pipeStats.TLSOtherErrs++
					}
					pipeStats.mu.Unlock()
					continue
				}
				pipeStats.TLSHandshake++

				// 3. H2 Protocol
				if cand != nil && cand.ALPN != "h2" {
					pipeStats.H2NoALPN++
				}

				if pErr != nil {
					errStr := pErr.Err.Error()
					if os.IsTimeout(pErr.Err) || strings.Contains(errStr, "deadline") || strings.Contains(errStr, "i/o timeout") || (cand != nil && cand.ReadTimeout) {
						pipeStats.H2TimeoutNoFrames++
					} else if strings.Contains(errStr, "connection reset") {
						pipeStats.H2ConnectionReset++
					} else if strings.Contains(errStr, "broken pipe") {
						pipeStats.H2BrokenPipe++
					} else if strings.Contains(errStr, "400 Bad Request") || strings.Contains(errStr, "HTTP/1.1") {
						pipeStats.H2BadRequest++
					} else if cand != nil && cand.GoAwaySeen {
						pipeStats.H2GoAway++
					} else if errors.Is(pErr.Err, io.EOF) || strings.Contains(errStr, "EOF") {
						pipeStats.H2EOF++
					} else if strings.Contains(errStr, "tls:") {
						pipeStats.H2TLSAlerts++
					} else {
						pipeStats.H2OtherErrs++
					}
					pipeStats.mu.Unlock()
					continue
				}

				if cand == nil || !cand.H2ProtocolConfirmed {
					pipeStats.H2OtherErrs++
					pipeStats.mu.Unlock()
					continue
				}
				pipeStats.H2ProtocolOK++

				// 4. H2 Headers
				if !cand.H2HeadersReceived {
					if cand.ReadTimeout {
						pipeStats.H2Timeouts++
					} else if cand.HPACKErrors {
						pipeStats.H2HPACKErrors++
					} else {
						pipeStats.H2OtherErrs++
					}
					pipeStats.mu.Unlock()
					continue
				}
				pipeStats.H2HeadersOK++

				// 5. H2 HTTP Status
				if cand.MissingStatus || cand.HTTPStatus <= 0 {
					pipeStats.H2InvalidStatus++
					pipeStats.mu.Unlock()
					continue
				}
				pipeStats.H2StatusOK++

				if cand.EndStreamSeen {
					pipeStats.EndStreamOK++
				}
				pipeStats.mu.Unlock()

				// 6. Score & Enrich
				if !validateAndEnrich(cand, cfg, pipeStats) {
					pipeStats.mu.Lock()
					pipeStats.ScoreRejected++
					pipeStats.mu.Unlock()
					continue
				}

				// 7. Success
				pipeStats.mu.Lock()
				pipeStats.CandidatesAccepted++
				pipeStats.mu.Unlock()

				candMu.Lock()
				candidates = append(candidates, *cand)
				candMu.Unlock()
			}
		}()
	}

	for _, p := range validPairs {
		h2jobs <- p
	}
	close(h2jobs)
	wgE.Wait()

	if ctx.Err() != nil {
		fmt.Println("[-] Выполнение прервано (Stage E).")
		return nil
	}

	ipClusters := make(map[string][]Candidate)
	for _, c := range candidates {
		ipClusters[c.IP] = append(ipClusters[c.IP], c)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		if candidates[i].Timings.TotalProbeLatency() != candidates[j].Timings.TotalProbeLatency() {
			return candidates[i].Timings.TotalProbeLatency() < candidates[j].Timings.TotalProbeLatency()
		}
		return candidates[i].SNI < candidates[j].SNI
	})

	s := pipeStats
	s.mu.Lock()
	fmt.Println("\n===================================================================================================================")
	fmt.Println("                                   ТЕЛЕМЕТРИЯ СКАНИРОВАНИЯ (PIPELINE STATS)")
	fmt.Println("===================================================================================================================")
	fmt.Printf("[*] IP отобрано для пула:      %d\n", s.IPSampled)
	fmt.Printf("[*] IP с чистым PTR (Hosts):   %d\n", s.PTRFound)
	fmt.Printf("[*] IP с сертификатами (TLS):  %d\n", s.IPWithDirectTLS)
	fmt.Printf("[*] Найдено уник. доменов:     %d\n\n", s.UniqueDomains)

	fmt.Printf("[*] Logical DNS Lookups:       %d (Успех: %d, Ошибок: %d)\n", s.DNSQueries, s.DNSSuccess, s.DNSFailed)
	fmt.Printf("    Детали DNS успехов:        Resolved IPs: %d, NXDOMAIN: %d, NoIPv4: %d\n", s.DNSResolvedIPs, s.DNSNXDomain, s.DNSNoIPv4)
	fmt.Printf("    Детали DNS ошибок:         Timeout: %d, Temporary: %d, Other: %d\n", s.DNSTimeout, s.DNSTemporary, s.DNSOtherErr)

	fmt.Println("    DNS resolver telemetry:")
	rtCaches.DNSStatsMu.Lock()
	resolverNames := make([]string, 0, len(rtCaches.DNSResolverStats))
	for resolver := range rtCaches.DNSResolverStats {
		resolverNames = append(resolverNames, resolver)
	}
	sort.Strings(resolverNames)
	for _, resolver := range resolverNames {
		st := rtCaches.DNSResolverStats[resolver]
		fmt.Printf("      %-16s attempts=%-4d answers=%-4d nx=%-4d fail=%-4d timeout=%-4d IPv4=%d\n", resolver, st.Attempts, st.Answers, st.NXDomain, st.Failures, st.Timeouts, st.IPv4s)
	}
	rtCaches.DNSStatsMu.Unlock()
	fmt.Printf("    Детали PTR запросов:       Sent: %d, Found: %d, Err: %d\n", s.PTRQueriesSent, s.PTRFound, s.PTRErrors)
	fmt.Printf("[*] Target Range IP Matches:   %d\n", s.DNSTargetRangeMatches)
	fmt.Printf("[*] Подтверждено DNS-пар:      %d\n\n", s.DNSValidPairs)

	fmt.Printf("[*] Анализ Stage E (Строгая Воронка):\n")
	fmt.Printf("    1. Целей на входе (DNS):       %d\n", s.DNSValidPairs)
	fmt.Printf("    2. Успешный TCP коннект:       %d (Потери: Timeouts=%d, Refused=%d, Other=%d)\n", s.TCPConnected, s.TCPTimeouts, s.TCPRefused, s.TCPOtherErrs)
	fmt.Printf("    3. Успешный TLS хэндшейк:      %d (Потери: Timeouts=%d, HandshakeFail=%d, UnrecName=%d, ConnReset=%d, EOF=%d, NoCert=%d, CertFail=%d, Other=%d)\n", s.TLSHandshake, s.TLSTimeouts, s.TLSHandshakeFailure, s.TLSUnrecognizedName, s.TLSConnectionReset, s.TLSEOF, s.NoPeerCertificates, s.TLSValidationFailures, s.TLSOtherErrs)
	fmt.Printf("    4. Подтверждён H2 протокол:    %d (Потери: TimeoutNoFrames=%d, ConnReset=%d, BrokenPipe=%d, BadRequest/HTTP1=%d, GoAway=%d, EOF=%d, TLSAlerts=%d, Other=%d)\n", s.H2ProtocolOK, s.H2TimeoutNoFrames, s.H2ConnectionReset, s.H2BrokenPipe, s.H2BadRequest, s.H2GoAway, s.H2EOF, s.H2TLSAlerts, s.H2OtherErrs)
	fmt.Printf("    5. Получены H2 Headers:        %d (Потери: TimeoutsNoHeaders=%d, HPACK_Err=%d)\n", s.H2HeadersOK, s.H2Timeouts, s.H2HPACKErrors)
	fmt.Printf("    6. Валидный HTTP Status:       %d (Потери: Invalid/Zero Status=%d)\n", s.H2StatusOK, s.H2InvalidStatus)
	fmt.Printf("    7. Финальные Кандидаты:        %d (Отклонено по Score=%d)\n", s.CandidatesAccepted, s.ScoreRejected)

	fmt.Printf("\n    *  Инфо: H2 целей без ALPN 'h2': %d\n", s.H2NoALPN)
	fmt.Printf("    *  Уникальных IP-кластеров:    %d\n", len(ipClusters))
	s.mu.Unlock()

	if cfg.DNSTrace {
		fmt.Printf("\n[*] DNS resolver aggregate telemetry:\n")
		rtCaches.DNSStatsMu.Lock()
		for _, resolver := range cfg.DNSResolvers {
			stat := rtCaches.DNSResolverStats[resolver]
			if stat == nil {
				continue
			}
			fmt.Printf("    %-15s attempts=%d answers=%d ipv4=%d nxdomain=%d failures=%d timeouts=%d\n", resolver, stat.Attempts, stat.Answers, stat.IPv4s, stat.NXDomain, stat.Failures, stat.Timeouts)
		}
		rtCaches.DNSStatsMu.Unlock()
	}

	return candidates
}

// ================= MAIN =================

func main() {
	cfg := Config{}
	var modeStr, domainsStr string

	flag.StringVar(&modeStr, "mode", "autonomous", "autonomous | direct")
	flag.IntVar(&cfg.Workers, "w", 1000, "Worker pool size for TLS/TCP probing")
	flag.IntVar(&cfg.DNSWorkers, "dns-workers", 128, "Worker pool size for DNS validation")
	flag.IntVar(&cfg.DNSQueryTimeoutMs, "dns-timeout", 1500, "Per-resolver raw UDP DNS timeout ms")
	flag.IntVar(&cfg.ECSPrefix, "ecs-prefix", 24, "EDNS Client Subnet IPv4 prefix length (0..32, default 24)")
	flag.BoolVar(&cfg.DNSTrace, "dns-trace", false, "Query every configured resolver for selected domains and print resolver -> A records")
	flag.IntVar(&cfg.DNSTraceLimit, "dns-trace-limit", 20, "Maximum number of unique domains to compare in -dns-trace (0 = unlimited)")
	var dnsResolversStr string
	flag.StringVar(&dnsResolversStr, "dns", DefaultDNSResolvers, "Comma-separated raw UDP DNS resolver IPv4 addresses")
	flag.IntVar(&cfg.MaxIPs, "max-ips", 0, "Limit for IP sampling (0 = no hard limit, will scan all generated IPs)")
	flag.IntVar(&cfg.TCPTimeoutMs, "tcp-timeout", 3000, "TCP timeout ms")
	flag.IntVar(&cfg.TLSTimeoutMs, "tls-timeout", 3000, "TLS timeout ms")
	flag.IntVar(&cfg.H2ReadTimeoutMs, "h2-read", 3000, "H2 Read timeout ms")
	flag.IntVar(&cfg.H2WriteTimeoutMs, "h2-write", 2000, "H2 Write timeout ms")
	flag.StringVar(&cfg.TargetCountry, "c", "", "Hard Filter: Target Country Code")
	flag.StringVar(&cfg.TargetASN, "asn", "", "Hard Filter: Target ASN constraint (e.g., AS12345)")
	flag.StringVar(&cfg.TargetIP, "vps-ip", "", "IP сервера для поиска сети (запуск с ПК); также используется как ECS IP, если -ecs-ip не задан")
	flag.StringVar(&cfg.ECSIP, "ecs-ip", "", "Explicit IPv4 address to place into EDNS Client Subnet")
	flag.StringVar(&cfg.DirectSNI, "sni", "", "Fallback SNI for Direct mode")
	flag.StringVar(&domainsStr, "domains", "", "Comma-separated seed domains for OSINT")

	flag.BoolVar(&cfg.NoPTR, "no-ptr", false, "Disable Reverse DNS PTR lookups")
	flag.BoolVar(&cfg.NoActiveTLS, "no-tls-probe", false, "Disable direct IP TLS certificate extraction")

	flag.Parse()

	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.DNSWorkers < 1 {
		cfg.DNSWorkers = 1
	}
	if cfg.DNSQueryTimeoutMs < 250 {
		cfg.DNSQueryTimeoutMs = 250
	}
	if cfg.ECSPrefix < 0 || cfg.ECSPrefix > 32 {
		log.Fatalf("[-] -ecs-prefix must be between 0 and 32")
	}
	if cfg.DNSTraceLimit < 0 {
		cfg.DNSTraceLimit = 0
	}
	cfg.DNSResolvers = normalizeDNSResolvers(strings.Split(dnsResolversStr, ","))
	if len(cfg.DNSResolvers) == 0 {
		log.Fatal("[-] DNS resolver pool is empty; use -dns with IPv4 addresses")
	}
	cfg.Mode = Mode(modeStr)
	cfg.CIDRs = flag.Args()

	if domainsStr != "" {
		for _, d := range strings.Split(domainsStr, ",") {
			if cleaned := CleanDomain(d); cleaned != "" {
				cfg.Domains = append(cfg.Domains, cleaned)
			}
		}
	}

	if cfg.Mode != ModeAuto && cfg.Mode != ModeDirect {
		log.Fatalf("[-] Unknown mode: %s", cfg.Mode)
	}
	if cfg.Mode == ModeDirect {
		if len(cfg.CIDRs) == 0 {
			log.Fatal("[-] Direct mode requires at least one IPv4 CIDR")
		}
		if CleanDomain(cfg.DirectSNI) == "" {
			log.Fatal("[-] Direct mode requires -sni target explicitly")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var vpsQueryIP string

	// ECS identity:
	//   1) explicit -ecs-ip
	//   2) -vps-ip
	//   3) detected public IPv4
	// The same ECS IP is used for every Stage D DNS query in this run.
	if cfg.ECSIP != "" {
		parsed := net.ParseIP(cfg.ECSIP)
		if parsed == nil || parsed.To4() == nil {
			log.Fatalf("[-] Invalid -ecs-ip: %s", cfg.ECSIP)
		}
		cfg.ECSIP = parsed.To4().String()
	} else if cfg.TargetIP != "" {
		parsed := net.ParseIP(cfg.TargetIP)
		if parsed != nil && parsed.To4() != nil {
			cfg.ECSIP = parsed.To4().String()
		}
	}
	if cfg.ECSIP == "" {
		ip, err := getPublicIP("")
		if err != nil {
			log.Fatalf("[-] ECS IP detection failed: %v", err)
		}
		cfg.ECSIP = ip
	}

	if cfg.Mode == ModeAuto {
		vpsQueryIP = cfg.TargetIP
		if vpsQueryIP == "" {
			vpsQueryIP = cfg.ECSIP
		}

		if cfg.TargetASN == "" || cfg.TargetCountry == "" {
			asn, _ := getASNAndPrefix(vpsQueryIP)
			country := getCountry(vpsQueryIP)
			if cfg.TargetASN == "" {
				cfg.TargetASN = asn
			}
			if cfg.TargetCountry == "" {
				cfg.TargetCountry = country
			}
		}
	}

	maskedECSIP := cfg.ECSIP
	if parsed := net.ParseIP(cfg.ECSIP); parsed != nil && parsed.To4() != nil {
		masked := append(net.IP(nil), parsed.To4()...)
		usedBytes := (cfg.ECSPrefix + 7) / 8
		if usedBytes > 0 && cfg.ECSPrefix%8 != 0 {
			masked[usedBytes-1] &= byte(0xFF << uint(8-(cfg.ECSPrefix%8)))
		}
		for i := usedBytes; i < 4; i++ {
			masked[i] = 0
		}
		if cfg.ECSPrefix == 0 {
			masked[0], masked[1], masked[2], masked[3] = 0, 0, 0, 0
		}
		maskedECSIP = net.IP(masked).String()
	}
	fmt.Printf("[*] ECS client IP:          %s/%d (wire=%s/%d)\n", cfg.ECSIP, cfg.ECSPrefix, maskedECSIP, cfg.ECSPrefix)
	fmt.Printf("[*] Raw UDP DNS pool:       %s\n", strings.Join(cfg.DNSResolvers, ", "))
	fmt.Printf("[*] ECS mode:               RFC7871 IPv4, scope=0; use -ecs-prefix 32 for host-specific ECS\n")
	if cfg.DNSTrace {
		limitText := "unlimited"
		if cfg.DNSTraceLimit > 0 {
			limitText = strconv.Itoa(cfg.DNSTraceLimit)
		}
		fmt.Printf("[*] DNS resolver compare:   enabled (unique domains: %s; all resolvers queried)\n", limitText)
	}

	var results []Candidate

	if cfg.Mode == ModeAuto {
		allPrefixes := getPrefixes(cfg.TargetASN)
		if len(allPrefixes) == 0 {
			log.Fatalf("[-] Failed to fetch CIDRs for %s", cfg.TargetASN)
		}

		var targetPrefixes []string
		if cfg.TargetCountry != "" && cfg.TargetCountry != "UNKNOWN" {
			targetPrefixes = filterPrefixesByCountry(allPrefixes, cfg.TargetCountry)

			vpsIPObj := net.ParseIP(vpsQueryIP)
			foundLocal := false
			var localPrefix string
			for _, c := range allPrefixes {
				_, ipnet, _ := net.ParseCIDR(c)
				if ipnet != nil && ipnet.Contains(vpsIPObj) {
					localPrefix = c
					break
				}
			}

			for _, p := range targetPrefixes {
				if p == localPrefix {
					foundLocal = true
					break
				}
			}
			if !foundLocal && localPrefix != "" {
				targetPrefixes = append([]string{localPrefix}, targetPrefixes...)
			}
		} else {
			targetPrefixes = allPrefixes
		}

		sampledIPs := generateIPs(targetPrefixes, cfg.MaxIPs)

		dnsRanges := MergeCIDRs(allPrefixes)

		fmt.Printf("[*] Целевой IP:             %s\n", vpsQueryIP)
		fmt.Printf("[*] Announcing ASN:         %s\n", cfg.TargetASN)
		fmt.Printf("[*] Фокус на префиксы:       %d подсетей ASN (С учетом страны)\n", len(targetPrefixes))
		fmt.Printf("[*] Страна сервера:          %s (ip-api)\n", cfg.TargetCountry)
		fmt.Printf("[*] ВНИМАНИЕ: DNS валидация проверяет все %d префиксов ASN для расширения покрытия.\n", len(allPrefixes))
		fmt.Printf("[*] Подготовлено %d IP адресов для сэмплинга. Запуск...\n\n", len(sampledIPs))

		results = RunPipeline(ctx, cfg, sampledIPs, dnsRanges)

	} else if cfg.Mode == ModeDirect {
		merged := MergeCIDRs(cfg.CIDRs)
		sampledIPs := generateIPs(cfg.CIDRs, cfg.MaxIPs)
		fmt.Printf("[*] Direct Mode: Подготовлено %d IP адресов. Запуск...\n", len(sampledIPs))
		results = RunPipeline(ctx, cfg, sampledIPs, merged)
	}

	if len(results) == 0 {
		fmt.Println("\n[-] Подходящих кандидатов не найдено.")
		return
	}

	fmt.Printf("\n[+] Найдено валидных HTTP/2 целей (после кластеризации): %d\n\n", len(results))
	fmt.Printf("%-36s | %-15s | %-5s | %-4s | %-4s | %-4s | %-4s | %-4s | %-5s | %-6s | %4s %4s %4s\n",
		"Цель (SNI)", "IP адрес", "SCORE", "TLS", "CERT", "H2", "SRV", "HTTP", "DSCOV", "STATUS", "TCP", "TLS", "H2")
	fmt.Println(strings.Repeat("-", 126))

	for _, r := range results {
		rs := r.RealityScore
		scoreStr := fmt.Sprintf("%.1f", r.Score)

		fmt.Printf("%-36s | %-15s | %-5s | %2.0f   | %2.0f   | %2.0f   | %2.0f   | %2.0f   | %2.0f    | %-6d | %3d %3d %3d\n",
			limitStr(r.SNI, 36), r.IP, scoreStr, rs.TLSQuality, rs.Certificate, rs.H2Profile, rs.ServerProfile, rs.HTTPBehavior, rs.DiscoveryScore, r.HTTPStatus,
			r.Timings.TCP.Milliseconds(), r.Timings.TLS.Milliseconds(), r.Timings.H2Headers.Milliseconds())
	}

	best := results[0]
	fmt.Println("\n===================================================================================================================")
	fmt.Println("                                   РЕКОМЕНДУЕМАЯ КОНФИГУРАЦИЯ DEST/SNI")
	fmt.Println("===================================================================================================================")
	fmt.Printf("\"dest\": \"%s:443\",\n", best.SNI)
	fmt.Printf("\"serverNames\": [\n  \"%s\"\n]\n\n", best.SNI)
	fmt.Printf("Подробности лучшего кандидата:\n")
	fmt.Printf("TLS: %.0f/20 | CERT: %.0f/20 | H2: %.0f/20 | SERVER: %.0f/10 | HTTP: %.0f/10 | DSCOV: %.0f/10 | LATENCY: TCP %dms, TLS %dms, H2 %dms\n",
		best.RealityScore.TLSQuality, best.RealityScore.Certificate, best.RealityScore.H2Profile, best.RealityScore.ServerProfile, best.RealityScore.HTTPBehavior, best.RealityScore.DiscoveryScore,
		best.Timings.TCP.Milliseconds(), best.Timings.TLS.Milliseconds(), best.Timings.H2Headers.Milliseconds())
	fmt.Printf("-------------------------------------------------------------------------------------------------------------------\n")
	fmt.Printf("BASE SCORE: %.1f | PENALTY: -%.1f | FINAL REALITY SCORE: %.1f/100 (HTTP: %d, Total Probe Latency: %d ms)\n",
		best.RealityScore.Total, best.DomainPenalty, best.Score, best.HTTPStatus, best.Timings.TotalProbeLatency().Milliseconds())
}
