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
	"sync/atomic"
	"syscall"
	"time"

	dnscrypt "github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	mdns "github.com/miekg/dns"
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

	dnsFastPoolSize = 128

	LimitMaxIPs          = 262144
	MaxDiscoveredDomains = 50000
	LimitValidPairs      = 10000
	MaxHostsPer24        = 254
	MaxSampled24         = 4
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
	stampRe  = regexp.MustCompile(`^sdns://[A-Za-z0-9_-]+=*$`)

	ErrDNSNXDomain = errors.New("NXDOMAIN")

	uaRng *rand.Rand
	uaMu  sync.Mutex
)

type Config struct {
	Mode             Mode
	Workers          int
	DNSWorkers       int
	MaxIPs           int
	TCPTimeoutMs     int
	TLSTimeoutMs     int
	H2ReadTimeoutMs  int
	H2WriteTimeoutMs int
	Seed             int64
	TargetASN        string
	TargetCountry    string
	TargetIP         string
	DirectSNI        string
	CIDRs            []string
	Domains          []string
	NoPTR            bool
	NoActiveTLS      bool
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
	mu                    sync.Mutex
	IPSampled             int
	ActiveProbes          int
	UniqueDomains         int
	DNSQueries            int
	DNSSuccess            int
	DNSFailed             int
	DNSNXDomain           int
	DNSTimeout            int
	DNSTemporary          int
	DNSNoIPv4             int
	DNSOtherErr           int
	DNSResolvedIPs        int
	DNSUniqueResolvedIPs  int
	DNSUniqueTargetIPs    int
	DNSTargetRangeMatches int
	DNSTargetDomains      int
	DNSValidPairs         int
	TCPConnected          int
	TLSHandshake          int
	NoPeerCertificates    int
	TLSValidationFailures int
	H2ProtocolOK          int
	H2HeadersOK           int
	EndStreamOK           int
	H2HPACKErrors         int
	H2Timeouts            int
	H2InvalidStatus       int
	ScoreRejected         int
	IPWithPTR             int
	IPWithDirectTLS       int

	PTRQueriesSent int
	PTRNoError     int
	PTRNXDomain    int
	PTREmptyAnswer int
	PTRErrors      int
}

func NewPipelineStats() *PipelineStats {
	return &PipelineStats{}
}

type RuntimeCaches struct {
	DNSCache *SafeDNSCache
	DNSGroup *singleflight.Group
}

func NewRuntimeCaches() *RuntimeCaches {
	return &RuntimeCaches{
		DNSCache: NewSafeDNSCache(),
		DNSGroup: &singleflight.Group{},
	}
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

// ================= DNSCRYPT POOL =================
const dnsPoolCacheFile = "dnscrypt_pool.json"
const requiredDNSProps = dnsstamps.ServerInformalPropertyNoLog | dnsstamps.ServerInformalPropertyNoFilter

var resolverListURLsV3 = []string{
	"https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md",
	"https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
}

type DNSResolver struct {
	Stamp              string
	Info               *dnscrypt.ResolverInfo
	RTT                time.Duration
	Success            atomic.Uint64
	Failures           atomic.Uint64
	ConsecutiveFailure atomic.Uint64
	mu                 sync.Mutex
	DisabledTo         time.Time
}

func (r *DNSResolver) getInfo() *dnscrypt.ResolverInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Info
}

func (r *DNSResolver) refresh() error {
	client := &dnscrypt.Client{Net: "udp", Timeout: 3 * time.Second}
	info, err := client.Dial(r.Stamp)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.Info = info
	r.mu.Unlock()
	return nil
}

type DNSPool struct {
	mu             sync.RWMutex
	resolvers      []*DNSResolver
	Discovered     atomic.Uint64
	Checked        atomic.Uint64
	Healthy        atomic.Uint64
	LogicalQueries atomic.Uint64
	Queries        atomic.Uint64
	Successes      atomic.Uint64
	Failures       atomic.Uint64
	Retries        atomic.Uint64
	rngMu          sync.Mutex
	rng            *rand.Rand
	sem            chan struct{} // Семафор для защиты от шторма UDP-сокетов
}

type StampCache struct {
	Timestamp time.Time `json:"timestamp"`
	Stamps    []string  `json:"stamps"`
}

func parseResolverList(body string) []string {
	lines := strings.Split(body, "\n")
	seen := make(map[string]struct{})
	var stamps []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !stampRe.MatchString(line) {
			continue
		}
		stamp, err := dnsstamps.NewServerStampFromString(line)
		if err != nil || stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt || stamp.Props&requiredDNSProps != requiredDNSProps {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		stamps = append(stamps, line)
	}
	return stamps
}

func downloadResolverList(ctx context.Context, urlStr string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	return parseResolverList(string(body)), nil
}

func loadResolverStamps(ctx context.Context) ([]string, error) {
	if data, err := os.ReadFile(dnsPoolCacheFile); err == nil {
		var cache StampCache
		if err := json.Unmarshal(data, &cache); err == nil {
			if time.Since(cache.Timestamp) < 12*time.Hour && len(cache.Stamps) > 0 {
				fmt.Printf("[DNS] Загружено %d stamps из локального кэша\n", len(cache.Stamps))
				return cache.Stamps, nil
			}
		}
	}
	var all []string
	for _, urlStr := range resolverListURLsV3 {
		stamps, err := downloadResolverList(ctx, urlStr)
		if err == nil {
			all = append(all, stamps...)
		}
	}
	all = uniqueStrings(all)
	if len(all) == 0 {
		return nil, fmt.Errorf("no DNSCrypt resolvers found")
	}
	cacheData, err := json.Marshal(StampCache{Timestamp: time.Now(), Stamps: all})
	if err == nil {
		_ = os.WriteFile(dnsPoolCacheFile, cacheData, 0644)
	}
	return all, nil
}

func checkDNSResolver(ctx context.Context, stamp string) (*DNSResolver, error) {
	client := &dnscrypt.Client{Net: "udp", Timeout: 3 * time.Second}
	info, err := client.Dial(stamp)
	if err != nil {
		return nil, err
	}
	tests := []struct {
		Name      string
		Type      uint16
		WantRcode int
	}{
		{"example.com.", mdns.TypeA, mdns.RcodeSuccess},
		{"cloudflare.com.", mdns.TypeA, mdns.RcodeSuccess},
	}
	var totalRTT time.Duration
	for _, t := range tests {
		req := new(mdns.Msg)
		req.Id = mdns.Id()
		req.SetQuestion(t.Name, t.Type)
		req.RecursionDesired = true
		qStart := time.Now()
		resp, err := client.Exchange(req, info)
		if err != nil || resp == nil || resp.Rcode != t.WantRcode {
			return nil, fmt.Errorf("bad response")
		}
		totalRTT += time.Since(qStart)
	}
	return &DNSResolver{Stamp: stamp, Info: info, RTT: totalRTT / 2}, nil
}

func buildDNSPool(ctx context.Context, stamps []string, dnsWorkers int) *DNSPool {
	pool := &DNSPool{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
		sem: make(chan struct{}, dnsWorkers), // ИСПРАВЛЕНИЕ: Семафор для защиты пула
	}
	pool.Discovered.Store(uint64(len(stamps)))

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(64)

	for _, stamp := range stamps {
		stamp := stamp
		g.Go(func() error {
			r, err := checkDNSResolver(gctx, stamp)
			pool.Checked.Add(1)
			if err == nil {
				pool.Healthy.Add(1)
				mu.Lock()
				pool.resolvers = append(pool.resolvers, r)
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	pool.mu.Lock()
	sort.Slice(pool.resolvers, func(i, j int) bool {
		return pool.resolvers[i].RTT < pool.resolvers[j].RTT
	})
	pool.mu.Unlock()
	return pool
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (p *DNSPool) pickWeighted() *DNSResolver {
	p.mu.RLock()
	var available []*DNSResolver
	now := time.Now()
	for _, r := range p.resolvers {
		r.mu.Lock()
		disabled := now.Before(r.DisabledTo)
		r.mu.Unlock()
		if !disabled {
			available = append(available, r)
		}
	}
	p.mu.RUnlock()

	// ИСПРАВЛЕНИЕ: Self-healing. Если все упали, мгновенно оживляем весь пул
	if len(available) == 0 {
		p.mu.Lock()
		for _, r := range p.resolvers {
			r.mu.Lock()
			r.DisabledTo = time.Time{}
			r.ConsecutiveFailure.Store(0)
			r.mu.Unlock()
			available = append(available, r)
		}
		p.mu.Unlock()
	}

	n := len(available)
	if n > dnsFastPoolSize {
		n = dnsFastPoolSize
	}

	var weights []int
	totalWeight := 0
	for i := 0; i < n; i++ {
		r := available[i]
		r.mu.Lock()
		rtt := r.RTT.Milliseconds()
		r.mu.Unlock()

		success := r.Success.Load()
		failures := r.Failures.Load()
		totalReqs := success + failures
		if totalReqs == 0 {
			totalReqs = 1
		}
		failureRate := float64(failures) / float64(totalReqs)

		weight := 1000 / int(max64(10, rtt))
		if weight < 1 {
			weight = 1
		}
		if failureRate > 0.30 {
			weight /= 4
		} else if failureRate > 0.10 {
			weight /= 2
		}
		if weight < 1 {
			weight = 1
		}

		weights = append(weights, weight)
		totalWeight += weight
	}

	p.rngMu.Lock()
	x := p.rng.Intn(totalWeight)
	p.rngMu.Unlock()

	for i, w := range weights {
		if x < w {
			return available[i]
		}
		x -= w
	}
	return available[0]
}

func (p *DNSPool) resolverFailure(r *DNSResolver) uint64 {
	r.Failures.Add(1)
	n := r.ConsecutiveFailure.Add(1)
	if n >= 3 {
		r.mu.Lock()
		r.DisabledTo = time.Now().Add(5 * time.Minute)
		r.mu.Unlock()
	}
	return n
}

func (p *DNSPool) exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, *DNSResolver, time.Duration, error) {
	// ИСПРАВЛЕНИЕ: Ждем свободного слота (защита от локального UDP шторма)
	p.sem <- struct{}{}
	defer func() { <-p.sem }()

	p.LogicalQueries.Add(1)
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		p.Queries.Add(1)
		if attempt > 0 {
			p.Retries.Add(1)
		}

		resolver := p.pickWeighted()
		if resolver == nil {
			return nil, nil, 0, fmt.Errorf("DNSCrypt pool is empty")
		}

		client := &dnscrypt.Client{Net: "udp", Timeout: 2500 * time.Millisecond}
		info := resolver.getInfo()
		req.Id = mdns.Id() // Явно генерируем ID для каждого ретрая

		type exRes struct {
			resp *mdns.Msg
			err  error
		}
		ch := make(chan exRes, 1)

		start := time.Now()
		go func() {
			resp, err := client.Exchange(req, info)
			ch <- exRes{resp, err}
		}()

		var resp *mdns.Msg
		var err error
		select {
		case <-ctx.Done():
			return nil, nil, 0, ctx.Err()
		case res := <-ch:
			resp, err = res.resp, res.err
		}
		elapsed := time.Since(start)

		if err != nil {
			// ИСПРАВЛЕНИЕ: Не штрафуем резолверы за локальную отмену контекста
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, 0, err
			}

			failures := p.resolverFailure(resolver)
			if failures == 2 {
				if refreshErr := resolver.refresh(); refreshErr == nil {
					info = resolver.getInfo()
					start = time.Now()
					ch2 := make(chan exRes, 1)
					go func() {
						r, e := client.Exchange(req, info)
						ch2 <- exRes{r, e}
					}()
					select {
					case <-ctx.Done():
						return nil, nil, 0, ctx.Err()
					case res := <-ch2:
						resp, err = res.resp, res.err
					}
					elapsed = time.Since(start)
					if err == nil {
						resolver.ConsecutiveFailure.Store(0)
					} else {
						p.resolverFailure(resolver)
					}
				}
			}
			if err != nil {
				lastErr = err
				continue
			}
		}

		switch resp.Rcode {
		case mdns.RcodeSuccess, mdns.RcodeNameError:
			resolver.Success.Add(1)
			resolver.ConsecutiveFailure.Store(0)
			resolver.mu.Lock()
			if resolver.RTT == 0 {
				resolver.RTT = elapsed
			} else {
				resolver.RTT = (resolver.RTT*7 + elapsed) / 8
			}
			resolver.mu.Unlock()
			p.Successes.Add(1)
			return resp, resolver, elapsed, nil
		case mdns.RcodeServerFailure, mdns.RcodeRefused:
			lastErr = fmt.Errorf("servfail/refused")
			p.resolverFailure(resolver)
			continue
		default:
			lastErr = fmt.Errorf("rcode=%s", mdns.RcodeToString[resp.Rcode])
			p.resolverFailure(resolver)
			continue
		}
	}
	p.Failures.Add(1)
	return nil, nil, 0, lastErr
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
	var result struct {
		CountryCode string `json:"countryCode"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return strings.ToUpper(result.CountryCode)
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
	if targetCountry == "" || len(prefixes) == 0 {
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
	req.Header.Set("User-Agent", "Mozilla/5.0")
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

func extractDomainsFromTLS(ctx context.Context, ip, sni string, timeout time.Duration) []string {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil
	}
	defer conn.Close()

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	uConn.SetDeadline(time.Now().Add(timeout))
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil
	}

	state := uConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
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

	return uniqueStrings(doms)
}

func activeProbeIP(ctx context.Context, ip string, pool *DNSPool, timeout time.Duration, noPTR bool, noTLS bool, pipeStats *PipelineStats) map[string]DomainSource {
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

	// 1. DIRECT TLS
	if !noTLS {
		doms := extractDomainsFromTLS(ctx, ip, ip, timeout)
		if len(doms) > 0 && len(doms) <= 15 {
			for _, d := range doms {
				addDomain(d, SourceDirectTLS)
			}
		}
	}

	// 2. PTR
	if !noPTR {
		rev, err := reverseIPv4(ip)
		if err == nil {
			req := new(mdns.Msg)
			req.Id = mdns.Id()
			req.SetQuestion(rev, mdns.TypePTR)
			req.RecursionDesired = true

			pipeStats.mu.Lock()
			pipeStats.PTRQueriesSent++
			pipeStats.mu.Unlock()

			resp, _, _, err := pool.exchange(ctx, req)
			if err != nil {
				pipeStats.mu.Lock()
				pipeStats.PTRErrors++
				pipeStats.mu.Unlock()
			} else {
				switch resp.Rcode {
				case mdns.RcodeSuccess:
					pipeStats.mu.Lock()
					pipeStats.PTRNoError++
					if len(resp.Answer) == 0 {
						pipeStats.PTREmptyAnswer++
					}
					pipeStats.mu.Unlock()

					for _, ans := range resp.Answer {
						if ptr, ok := ans.(*mdns.PTR); ok {
							ptrDomain := strings.TrimSuffix(strings.TrimSpace(ptr.Ptr), ".")
							ptrDomain = CleanDomain(ptrDomain)
							if ptrDomain != "" {
								addDomain(ptrDomain, SourcePTR)

								if !noTLS {
									cDoms := extractDomainsFromTLS(ctx, ip, ptrDomain, timeout)
									for _, cd := range cDoms {
										addDomain(cd, SourceDirectTLS)
									}
								}
							}
						}
					}
				case mdns.RcodeNameError:
					pipeStats.mu.Lock()
					pipeStats.PTRNXDomain++
					pipeStats.mu.Unlock()
				default:
					pipeStats.mu.Lock()
					pipeStats.PTRErrors++
					pipeStats.mu.Unlock()
				}
			}
		}
	}

	// 3. OSINT
	if len(allDoms) < 5 {
		osints := getOSINTDomains(ip)
		for _, osint := range osints {
			osint = CleanDomain(osint)
			if osint == "" {
				continue
			}
			addDomain(osint, SourceSeed)

			if !noTLS {
				cDoms := extractDomainsFromTLS(ctx, ip, osint, timeout)
				if len(cDoms) > 0 {
					for _, cd := range cDoms {
						addDomain(cd, SourceDirectTLS)
					}
					break
				}
			}
		}
	}

	// 4. ДЕДУПЛИКАЦИЯ И УМНАЯ ОБРЕЗКА (max 5)
	uniqueDoms := uniqueStrings(allDoms)
	
	sort.Slice(uniqueDoms, func(i, j int) bool {
		srcI := sourceMap[uniqueDoms[i]]
		srcJ := sourceMap[uniqueDoms[j]]
		
		weight := func(s DomainSource) int {
			w := 0
			if s.Has(SourceDirectTLS) { w += 3 }
			if s.Has(SourcePTR) { w += 2 }
			if s.Has(SourceSeed) { w += 1 }
			return w
		}
		
		wi, wj := weight(srcI), weight(srcJ)
		if wi != wj {
			return wi > wj
		}
		return uniqueDoms[i] < uniqueDoms[j]
	})

	if len(uniqueDoms) > 5 {
		uniqueDoms = uniqueDoms[:5]
	}

	result := make(map[string]DomainSource, len(uniqueDoms))
	for _, d := range uniqueDoms {
		result[d] = sourceMap[d]
	}

	return result
}

func resolveIPv4DNSCrypt(ctx context.Context, pool *DNSPool, domain string) ([]string, error) {
	req := new(mdns.Msg)
	req.Id = mdns.Id()
	req.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
	req.RecursionDesired = true
	resp, _, _, err := pool.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == mdns.RcodeNameError {
		return nil, ErrDNSNXDomain
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code: %s", mdns.RcodeToString[resp.Rcode])
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, answer := range resp.Answer {
		if a, ok := answer.(*mdns.A); ok {
			ip := a.A.String()
			if _, exists := seen[ip]; !exists {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func resolveIPv4Cached(ctx context.Context, pool *DNSPool, domain string, rtCaches *RuntimeCaches) ([]string, error) {
	domain = CleanDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("invalid domain")
	}
	v, err, _ := rtCaches.DNSGroup.Do(domain, func() (interface{}, error) {
		if cached, ok := rtCaches.DNSCache.Get(domain); ok {
			if cached.NXDomain {
				return nil, ErrDNSNXDomain
			}
			return cached.IPs, nil
		}
		ips, err := resolveIPv4DNSCrypt(ctx, pool, domain)
		if errors.Is(err, ErrDNSNXDomain) {
			rtCaches.DNSCache.Put(domain, &DNSCacheEntry{NXDomain: true}, 1*time.Minute)
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		rtCaches.DNSCache.Put(domain, &DNSCacheEntry{IPs: ips}, 5*time.Minute)
		return ips, nil
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
	ua := []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
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
	if !cand.H2ProtocolConfirmed || !cand.H2HeadersReceived || cand.MissingStatus || cand.HTTPStatus <= 0 {
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

func RunPipeline(ctx context.Context, cfg Config, sampledIPs []string, scanRanges []ipRange, pool *DNSPool) []Candidate {
	pipeStats := NewPipelineStats()
	pipeStats.mu.Lock()
	pipeStats.IPSampled = len(sampledIPs)
	pipeStats.mu.Unlock()

	rtCaches := NewRuntimeCaches()

	discoveredDomains := make(map[string]DomainSource)
	var discoveredMu sync.Mutex

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

			results := activeProbeIP(gCtxA, ip, pool, time.Duration(cfg.TLSTimeoutMs)*time.Millisecond, cfg.NoPTR, cfg.NoActiveTLS, pipeStats)
			if len(results) > 0 {
				hasPTR := false
				hasTLS := false
				discoveredMu.Lock()
				for dom, src := range results {
					discoveredDomains[dom] |= src
					if src.Has(SourcePTR) {
						hasPTR = true
					}
					if src.Has(SourceDirectTLS) {
						hasTLS = true
					}
				}
				discoveredMu.Unlock()

				pipeStats.mu.Lock()
				if hasPTR {
					pipeStats.IPWithPTR++
				}
				if hasTLS {
					pipeStats.IPWithDirectTLS++
				}
				pipeStats.mu.Unlock()
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
			discoveredMu.Lock()
			discoveredDomains[cleaned] |= SourceSeed
			discoveredMu.Unlock()
		}
	}

	pipeStats.mu.Lock()
	pipeStats.UniqueDomains = len(discoveredDomains)
	pipeStats.mu.Unlock()

	fmt.Printf("[+] Этап A завершен. Найдено уникальных доменов: %d\n", len(discoveredDomains))
	if len(discoveredDomains) == 0 {
		return nil
	}

	var validPairs []TargetPair
	var pairSeen sync.Map
	var pairsMu sync.Mutex

	if cfg.Mode == ModeDirect && cfg.DirectSNI != "" {
		sni := CleanDomain(cfg.DirectSNI)
		if sni != "" {
			for _, ip := range sampledIPs {
				key := ip + "\x00" + sni
				if _, loaded := pairSeen.LoadOrStore(key, true); !loaded {
					pairsMu.Lock()
					validPairs = append(validPairs, TargetPair{
						IP:       ip,
						SNI:      sni,
						Evidence: SourceSeed,
					})
					pairsMu.Unlock()
				}
			}
		}
	}

	fmt.Printf("[*] STAGE D: DNS Validation (%d Domains)...\n", len(discoveredDomains))
	var uniqueResolvedIPs sync.Map
	var uniqueTargetIPs sync.Map

	gD, gCtxD := errgroup.WithContext(ctx)
	gD.SetLimit(cfg.DNSWorkers)
	for dom, src := range discoveredDomains {
		if cfg.Mode == ModeDirect && dom == CleanDomain(cfg.DirectSNI) {
			continue
		}
		dom := dom
		src := src
		gD.Go(func() error {
			if gCtxD.Err() != nil {
				return gCtxD.Err()
			}
			pipeStats.mu.Lock()
			pipeStats.DNSQueries++
			pipeStats.mu.Unlock()

			ips, err := resolveIPv4Cached(gCtxD, pool, dom, rtCaches)

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
				return nil
			}

			if len(ips) == 0 {
				pipeStats.DNSSuccess++
				pipeStats.DNSNoIPv4++
				pipeStats.mu.Unlock()
				return nil
			}

			pipeStats.DNSSuccess++
			pipeStats.DNSResolvedIPs += len(ips)
			pipeStats.mu.Unlock()

			matched := false
			for _, resolvedIP := range ips {
				uniqueResolvedIPs.Store(resolvedIP, struct{}{})

				if ipInRanges(resolvedIP, scanRanges) {
					uniqueTargetIPs.Store(resolvedIP, struct{}{})
					matched = true

					pipeStats.mu.Lock()
					pipeStats.DNSTargetRangeMatches++
					pipeStats.mu.Unlock()

					pairKey := resolvedIP + "\x00" + dom
					if _, loaded := pairSeen.LoadOrStore(pairKey, true); !loaded {
						pairsMu.Lock()
						if len(validPairs) < LimitValidPairs {
							validPairs = append(validPairs, TargetPair{
								IP:       resolvedIP,
								SNI:      dom,
								Evidence: src,
							})
						}
						pairsMu.Unlock()
					}
				}
			}
			if matched {
				pipeStats.mu.Lock()
				pipeStats.DNSTargetDomains++
				pipeStats.mu.Unlock()
			}
			return nil
		})
	}
	
	if err := gD.Wait(); err != nil || ctx.Err() != nil {
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
	gE, gCtxE := errgroup.WithContext(ctx)
	gE.SetLimit(cfg.Workers)

	for _, p := range validPairs {
		p := p
		gE.Go(func() error {
			if gCtxE.Err() != nil {
				return gCtxE.Err()
			}
			cand, pErr := ProbeH2(gCtxE, p.IP, p.SNI, p.Evidence, cfg)

			tcpOK := pErr == nil || pErr.Stage > ProbeStageTCP
			tlsOK := pErr == nil || pErr.Stage > ProbeStageTLS

			pipeStats.mu.Lock()
			if tcpOK {
				pipeStats.TCPConnected++
			}
			if tlsOK {
				pipeStats.TLSHandshake++
			}
			if cand != nil && cand.H2ProtocolConfirmed {
				pipeStats.H2ProtocolOK++
			}
			if cand != nil && cand.H2HeadersReceived {
				pipeStats.H2HeadersOK++
			}
			if cand != nil && cand.HPACKErrors {
				pipeStats.H2HPACKErrors++
			}
			if cand != nil && cand.ReadTimeout {
				pipeStats.H2Timeouts++
			}
			if cand != nil && cand.H2ProtocolConfirmed && (cand.MissingStatus || cand.HTTPStatus <= 0) {
				pipeStats.H2InvalidStatus++
			}

			if pErr != nil {
				if pErr.Stage == ProbeStageTLSValidation {
					if strings.Contains(pErr.Err.Error(), "no peer certificates") {
						pipeStats.NoPeerCertificates++
					} else {
						pipeStats.TLSValidationFailures++
					}
				}
				pipeStats.mu.Unlock()
				return nil
			}

			if cand != nil && cand.EndStreamSeen {
				pipeStats.EndStreamOK++
			}
			pipeStats.mu.Unlock()

			if !validateAndEnrich(cand, cfg, pipeStats) {
				pipeStats.mu.Lock()
				pipeStats.ScoreRejected++
				pipeStats.mu.Unlock()
				return nil
			}

			candMu.Lock()
			candidates = append(candidates, *cand)
			candMu.Unlock()
			return nil
		})
	}
	if err := gE.Wait(); err != nil || ctx.Err() != nil {
		fmt.Println("[-] Выполнение прервано (Stage E).")
		return nil
	}

	ipClusters := make(map[string][]Candidate)
	for _, c := range candidates {
		ipClusters[c.IP] = append(ipClusters[c.IP], c)
	}

	var clusteredCandidates []Candidate
	for _, cluster := range ipClusters {
		sort.Slice(cluster, func(i, j int) bool {
			if cluster[i].Score != cluster[j].Score {
				return cluster[i].Score > cluster[j].Score
			}
			if cluster[i].Timings.TotalProbeLatency() != cluster[j].Timings.TotalProbeLatency() {
				return cluster[i].Timings.TotalProbeLatency() < cluster[j].Timings.TotalProbeLatency()
			}
			return cluster[i].SNI < cluster[j].SNI
		})

		limit := len(cluster)
		if limit > 5 {
			limit = 5
		}
		for i := 0; i < limit; i++ {
			clusteredCandidates = append(clusteredCandidates, cluster[i])
		}
	}

	sort.Slice(clusteredCandidates, func(i, j int) bool {
		if clusteredCandidates[i].Score != clusteredCandidates[j].Score {
			return clusteredCandidates[i].Score > clusteredCandidates[j].Score
		}
		if clusteredCandidates[i].Timings.TotalProbeLatency() != clusteredCandidates[j].Timings.TotalProbeLatency() {
			return clusteredCandidates[i].Timings.TotalProbeLatency() < clusteredCandidates[j].Timings.TotalProbeLatency()
		}
		return clusteredCandidates[i].SNI < clusteredCandidates[j].SNI
	})

	s := pipeStats
	s.mu.Lock()
	fmt.Println("\n===================================================================================================================")
	fmt.Println("                                   ТЕЛЕМЕТРИЯ СКАНИРОВАНИЯ (PIPELINE STATS)")
	fmt.Println("===================================================================================================================")
	fmt.Printf("[*] IP отобрано для пула:      %d\n", s.IPSampled)
	fmt.Printf("[*] IP с чистым PTR (Hosts):   %d\n", s.IPWithPTR)
	fmt.Printf("[*] IP с сертификатами (TLS):  %d\n", s.IPWithDirectTLS)
	fmt.Printf("[*] Найдено уник. доменов:     %d\n\n", s.UniqueDomains)

	fmt.Printf("[*] Logical DNS Lookups:       %d (Успех: %d, Ошибок: %d)\n", s.DNSQueries, s.DNSSuccess, s.DNSFailed)
	fmt.Printf("    Детали DNS успехов:        Resolved IPs: %d, NXDOMAIN: %d, NoIPv4: %d\n", s.DNSResolvedIPs, s.DNSNXDomain, s.DNSNoIPv4)
	fmt.Printf("    Детали DNS ошибок:         Timeout: %d, Temporary: %d, Other: %d\n", s.DNSTimeout, s.DNSTemporary, s.DNSOtherErr)
	fmt.Printf("    Детали PTR запросов:       Sent: %d, NOERROR: %d, Empty: %d, NXDOMAIN: %d, Err: %d\n", s.PTRQueriesSent, s.PTRNoError, s.PTREmptyAnswer, s.PTRNXDomain, s.PTRErrors)
	fmt.Printf("[*] Target Range IP Matches:   %d\n", s.DNSTargetRangeMatches)
	fmt.Printf("[*] Подтверждено DNS-пар:      %d\n\n", s.DNSValidPairs)

	fmt.Printf("[*] Успешных TCP соединений:   %d\n", s.TCPConnected)
	fmt.Printf("[*] Успешных TLS хэндшейков:   %d\n", s.TLSHandshake)
	fmt.Printf("[*] Подтверждён протокол H2:   %d (любой H2 фрейм)\n", s.H2ProtocolOK)
	fmt.Printf("[*] С откликом H2 Headers:     %d\n", s.H2HeadersOK)
	fmt.Printf("    - С ошибками HPACK:        %d (игнорируются)\n", s.H2HPACKErrors)
	fmt.Printf("    - Таймаут чтения (спасён): %d (ранний выход)\n", s.H2Timeouts)
	fmt.Printf("    - Без валидного :status:   %d (отброшены)\n", s.H2InvalidStatus)
	fmt.Printf("    - Отклонено по Score (<0): %d\n", s.ScoreRejected)
	fmt.Printf("[*] Уникальных IP-кластеров:   %d\n", len(ipClusters))
	fmt.Printf("[*] Кандидатов в выводе:       %d\n", len(clusteredCandidates))
	s.mu.Unlock()

	return clusteredCandidates
}

// ================= MAIN =================

func main() {
	uaRng = rand.New(rand.NewSource(time.Now().UnixNano()))

	cfg := Config{}
	var modeStr, domainsStr string

	flag.StringVar(&modeStr, "mode", "autonomous", "autonomous | direct")
	flag.IntVar(&cfg.Workers, "w", 30, "Worker pool size for generic tasks")
	flag.IntVar(&cfg.DNSWorkers, "dns-workers", 128, "Worker pool size for DNS validation")
	flag.IntVar(&cfg.MaxIPs, "max-ips", 0, "Limit for IP sampling (0 = no hard limit, will scan all generated IPs)")
	flag.IntVar(&cfg.TCPTimeoutMs, "tcp-timeout", 2000, "TCP timeout ms")
	flag.IntVar(&cfg.TLSTimeoutMs, "tls-timeout", 2000, "TLS timeout ms")
	flag.IntVar(&cfg.H2ReadTimeoutMs, "h2-read", 3000, "H2 Read timeout ms")
	flag.IntVar(&cfg.H2WriteTimeoutMs, "h2-write", 2000, "H2 Write timeout ms")
	flag.Int64Var(&cfg.Seed, "seed", time.Now().UnixNano(), "Random seed")
	flag.StringVar(&cfg.TargetCountry, "c", "", "Hard Filter: Target Country Code")
	flag.StringVar(&cfg.TargetASN, "asn", "", "Hard Filter: Target ASN constraint (e.g., AS12345)")
	flag.StringVar(&cfg.TargetIP, "vps-ip", "", "IP сервера для поиска сети (запуск с ПК)")
	flag.StringVar(&cfg.DirectSNI, "sni", "", "Fallback SNI for Direct mode")
	flag.StringVar(&domainsStr, "domains", "", "Comma-separated seed domains for OSINT")

	flag.BoolVar(&cfg.NoPTR, "no-ptr", false, "Disable Reverse DNS PTR lookups")
	flag.BoolVar(&cfg.NoActiveTLS, "no-tls-probe", false, "Disable direct IP TLS certificate extraction")

	flag.Parse()

	if cfg.Seed != 0 {
		uaMu.Lock()
		uaRng = rand.New(rand.NewSource(cfg.Seed))
		uaMu.Unlock()
	}

	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.DNSWorkers < 1 {
		cfg.DNSWorkers = 1
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

	dnsCtx, dnsCancel := context.WithTimeout(ctx, 60*time.Second)
	defer dnsCancel()
	fmt.Println("[DNS] Загрузка публичного DNSCrypt pool...")
	stamps, err := loadResolverStamps(dnsCtx)
	if err != nil {
		log.Fatalf("[-] DNSCrypt list: %v", err)
	}

	dnsPool := buildDNSPool(dnsCtx, stamps, cfg.DNSWorkers)
	dnsPool.mu.RLock()
	poolSize := len(dnsPool.resolvers)
	dnsPool.mu.RUnlock()

	if poolSize < 5 {
		log.Fatalf("[-] Слишком мало рабочих DNSCrypt resolver'ов: %d", poolSize)
	}
	fmt.Printf("[+] Рабочий DNSCrypt pool: %d resolver'ов\n", poolSize)

	var vpsQueryIP string

	if cfg.Mode == ModeAuto {
		ip, err := getPublicIP(cfg.TargetIP)
		if err != nil {
			log.Fatalf("[-] %v\n", err)
		}
		vpsQueryIP = ip

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

	var results []Candidate

	if cfg.Mode == ModeAuto {
		allPrefixes := getPrefixes(cfg.TargetASN)
		if len(allPrefixes) == 0 {
			log.Fatalf("[-] Failed to fetch CIDRs for %s", cfg.TargetASN)
		}

		var targetPrefixes []string
		if cfg.TargetCountry != "" {
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

		results = RunPipeline(ctx, cfg, sampledIPs, dnsRanges, dnsPool)

	} else if cfg.Mode == ModeDirect {
		merged := MergeCIDRs(cfg.CIDRs)
		sampledIPs := generateIPs(cfg.CIDRs, cfg.MaxIPs)
		fmt.Printf("[*] Direct Mode: Подготовлено %d IP адресов. Запуск...\n", len(sampledIPs))
		results = RunPipeline(ctx, cfg, sampledIPs, merged, dnsPool)
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
