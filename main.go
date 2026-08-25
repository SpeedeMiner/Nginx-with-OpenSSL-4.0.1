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
	"github.com/oschwald/geoip2-golang"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/publicsuffix"
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

	dnsFastPoolSize = 32

	LimitMaxIPs          = 262144
	MaxDiscoveredDomains = 50000
	LimitValidPairs      = 10000
	MaxHostsPer24        = 254
	MaxSampled24         = 4
)

var (
	cdnStrong     = []string{"cloudflare", "fastly", "akamai", "ddos-guard", "qrator", "sucuri"}
	cdnWeak       = []string{"x-cache", "x-served-by", "x-edge"}
	bannedServers = []string{"cloudflare", "fastly", "akamai", "ddos-guard", "qrator", "sucuri"}

	bannedTLDs = map[string]bool{
		"crl": true, "ocsp": true, "der": true, "crt": true, "cer": true, "pem": true,
		"arpa": true, "local": true, "internal": true, "invalid": true, "example": true, "test": true, "localhost": true,
	}

	junkTLDs = []string{".xyz", ".top", ".site", ".fun", ".online", ".space", ".pw", ".cc", ".icu", ".click", ".win", ".bid", ".date"}
	dynDNS   = []string{"duckdns.org", "mooo.com", "ddns.net", "freeddns.org", "crabdance.com", "eu.org", "cloudns.cc", "hopto.org", "zapto.org", "sytes.net", "dyn.com", "no-ip.org"}

	domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	numRe    = regexp.MustCompile(`(?i)(^|\.)\d+\.[a-z]{2,}$`)
	stampRe  = regexp.MustCompile(`^sdns://[A-Za-z0-9_-]+=*$`)

	ErrProviderNoData = errors.New("provider returned no data")
	ErrDNSNXDomain    = errors.New("NXDOMAIN")

	uaRng *rand.Rand
	uaMu  sync.Mutex
)

type Config struct {
	Mode             Mode
	Workers          int
	MaxIPs           int
	TCPTimeoutMs     int
	TLSTimeoutMs     int
	H2ReadTimeoutMs  int
	H2WriteTimeoutMs int
	Seed             int64
	TargetASN        uint
	TargetCountry    string
	TargetIP         string
	DirectSNI        string
	ScanEntireASN    bool
	CIDRs            []string
	Domains          []string
	GeoIPPath        string
	ASNPath          string
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
	ASN                   uint
	Country               string
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
	DNSOtherErr           int
	DNSResolvedIPs        int
	DNSTargetRangeMatches int
	DNSValidPairs         int
	TCPConnected          int
	TLSHandshake          int
	NoPeerCertificates    int
	TLSValidationFailures int
	H2HeadersOK           int
	EndStreamOK           int
	ASNFiltered           int
	CountryFiltered       int
	IPWithPTR             int
	IPWithDirectTLS       int
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

func buildDNSPool(ctx context.Context, stamps []string) *DNSPool {
	pool := &DNSPool{rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
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
	defer p.mu.RUnlock()

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

	if len(available) == 0 {
		return nil
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

func GetRootDomain(domain string) string {
	domain = CleanDomain(domain)
	if domain == "" {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return root
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

// ================= ACTIVE RECON (TLS + PTR) =================

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

func activeProbeIP(ctx context.Context, ip string, pool *DNSPool, timeout time.Duration, noPTR bool, noTLS bool) map[string]DomainSource {
	results := make(map[string]DomainSource)

	if !noTLS {
		doms := extractDomainsFromTLS(ctx, ip, ip, timeout)
		if len(doms) > 0 && len(doms) <= 15 {
			for _, d := range doms {
				results[d] |= SourceDirectTLS
			}
			return results // CDN drop / fast exit
		}
	}

	if !noPTR {
		rev, err := reverseIPv4(ip)
		if err == nil {
			req := new(mdns.Msg)
			req.SetQuestion(rev, mdns.TypePTR)
			req.RecursionDesired = true
			if resp, _, _, err := pool.exchange(ctx, req); err == nil && resp.Rcode == mdns.RcodeSuccess {
				for _, ans := range resp.Answer {
					if ptr, ok := ans.(*mdns.PTR); ok {
						if d := CleanDomain(ptr.Ptr); d != "" {
							results[d] |= SourcePTR
							
							// Fallback TLS using PTR as SNI
							if !noTLS {
								cDoms := extractDomainsFromTLS(ctx, ip, d, timeout)
								if len(cDoms) > 0 && len(cDoms) <= 15 {
									for _, cd := range cDoms {
										results[cd] |= SourceDirectTLS
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return results
}

func resolvePTRDNSCrypt(ctx context.Context, pool *DNSPool, ip string) ([]string, error) {
	rev, err := reverseIPv4(ip)
	if err != nil {
		return nil, err
	}
	req := new(mdns.Msg)
	req.SetQuestion(rev, mdns.TypePTR)
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
	var names []string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*mdns.PTR); ok {
			if d := CleanDomain(ptr.Ptr); d != "" {
				names = append(names, d)
			}
		}
	}
	return names, nil
}

func resolveIPv4DNSCrypt(ctx context.Context, pool *DNSPool, domain string) ([]string, error) {
	req := new(mdns.Msg)
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
		req := new(mdns.Msg)
		req.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
		req.RecursionDesired = true
		resp, _, _, err := pool.exchange(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Rcode == mdns.RcodeNameError {
			rtCaches.DNSCache.Put(domain, &DNSCacheEntry{NXDomain: true}, 1*time.Minute)
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
		rtCaches.DNSCache.Put(domain, &DNSCacheEntry{IPs: ips}, 5*time.Minute)
		return ips, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

// ================= DB & IP HELPERS =================
func ensureDB(path, dbURL string) error {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1024*1024 {
		if db, err := geoip2.Open(path); err == nil {
			db.Close()
			return nil
		}
	}
	tempFile := path + ".tmp"
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(dbURL)
	if err != nil {
		out.Close()
		os.Remove(tempFile)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out.Close()
		os.Remove(tempFile)
		return fmt.Errorf("bad HTTP status: %d", resp.StatusCode)
	}
	if _, err = io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tempFile)
		return err
	}
	out.Close()
	testDB, err := geoip2.Open(tempFile)
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("invalid MaxMind database: %v", err)
	}
	testDB.Close()
	return os.Rename(tempFile, path)
}

func readPublicIPv4(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid IPv4: %s", ipStr)
	}
	return ip.To4().String(), nil
}

func getPublicIP(targetIP string) (string, error) {
	if targetIP != "" {
		ip := net.ParseIP(targetIP)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid target IPv4: %s", targetIP)
		}
		return ip.To4().String(), nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get("https://api.ipify.org"); err == nil {
		if ip, err := readPublicIPv4(resp); err == nil {
			return ip, nil
		}
	}
	if resp, err := client.Get("http://ip-api.com/line/?fields=query"); err == nil {
		if ip, err := readPublicIPv4(resp); err == nil {
			return ip, nil
		}
	}
	return "", fmt.Errorf("failed to fetch valid public IPv4")
}

type RipeStatResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func fetchASNCIDRs(asn uint) ([]string, error) {
	urlStr := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat HTTP %d", resp.StatusCode)
	}
	var stat RipeStatResponse
	if err := json.NewDecoder(resp.Body).Decode(&stat); err != nil {
		return nil, err
	}
	var cidrs []string
	for _, p := range stat.Data.Prefixes {
		if !strings.Contains(p.Prefix, ":") {
			if _, _, err := net.ParseCIDR(p.Prefix); err == nil {
				cidrs = append(cidrs, p.Prefix)
			}
		}
	}
	return cidrs, nil
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

func SampleIPs(blocks []ipRange, maxIPs int, seed int64) []string {
	var totalIPs uint64
	for _, b := range blocks {
		totalIPs += (b.end - b.start + 1)
	}
	if totalIPs == 0 {
		return nil
	}
	var sampleSize uint64
	switch {
	case maxIPs < -1:
		return nil
	case maxIPs == -1:
		sampleSize = totalIPs
	case maxIPs == 0:
		sampleSize = 1024
		if sampleSize > totalIPs {
			sampleSize = totalIPs
		}
	default:
		sampleSize = uint64(maxIPs)
		if sampleSize > totalIPs {
			sampleSize = totalIPs
		}
	}
	if sampleSize > LimitMaxIPs {
		sampleSize = LimitMaxIPs
	}
	if sampleSize == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed))
	currIdx := rng.Uint64() % totalIPs
	var step uint64 = 1
	if totalIPs > 1 {
		for {
			step = (rng.Uint64() % (totalIPs - 1)) + 1
			if gcd(step, totalIPs) == 1 {
				break
			}
		}
	}
	var result []string
	for i := uint64(0); i < sampleSize; i++ {
		offset := currIdx
		for _, b := range blocks {
			count := b.end - b.start + 1
			if offset < count {
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, uint32(b.start+offset))
				result = append(result, ip.String())
				break
			}
			offset -= count
		}
		currIdx = (currIdx + step) % totalIPs
	}
	return result
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

// ================= HTTP/2 PROBE =================

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
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)
	encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: sni})
	encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	encoder.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	encoder.WriteField(hpack.HeaderField{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"})
	encoder.WriteField(hpack.HeaderField{Name: "accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
	encoder.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "gzip, deflate, br"})
	return buf.Bytes()
}

func buildH2Frame(frameType, flags byte, streamId uint32, payload []byte) []byte {
	length := len(payload)
	header := make([]byte, 9)
	header[0], header[1], header[2] = byte(length>>16), byte(length>>8), byte(length)
	header[3], header[4] = frameType, flags
	binary.BigEndian.PutUint32(header[5:9], streamId&0x7FFFFFFF)
	return append(header, payload...)
}

func buildClientSettingsFrame() []byte {
	payload := make([]byte, 30)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint32(payload[2:6], 65536)
	binary.BigEndian.PutUint16(payload[6:8], 2)
	binary.BigEndian.PutUint32(payload[8:12], 0)
	binary.BigEndian.PutUint16(payload[12:14], 3)
	binary.BigEndian.PutUint32(payload[14:18], 1000)
	binary.BigEndian.PutUint16(payload[18:20], 4)
	binary.BigEndian.PutUint32(payload[20:24], 6291456)
	binary.BigEndian.PutUint16(payload[24:26], 6)
	binary.BigEndian.PutUint32(payload[26:30], 262144)
	return buildH2Frame(FrameSettings, 0, 0, payload)
}

func buildWindowUpdateFrame(streamID uint32, increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment&0x7FFFFFFF)
	return buildH2Frame(FrameWindowUpdate, 0, streamID, payload)
}

func parseResponseHeaders(cand *Candidate, headers []hpack.HeaderField) error {
	weakCount := 0
	blockStatus := 0
	hasStatus := false

	for _, h := range headers {
		hName := strings.ToLower(strings.TrimSpace(h.Name))

		if hName == ":status" {
			n, err := strconv.Atoi(strings.TrimSpace(h.Value))
			if err != nil {
				return fmt.Errorf("invalid :status value %q: %w", h.Value, err)
			}
			if n < 100 || n > 999 {
				return fmt.Errorf("invalid HTTP status: %d", n)
			}
			blockStatus = n
			hasStatus = true
		}
	}

	if !hasStatus {
		return fmt.Errorf("response HEADERS missing :status")
	}

	isInformational := blockStatus >= 100 && blockStatus < 200
	isFinalResponse := blockStatus >= 200

	if isInformational {
		return nil
	}

	if isFinalResponse && !cand.ResponseHeadersParsed {
		cand.HTTPStatus = blockStatus
		cand.ResponseHeadersParsed = true

		for _, h := range headers {
			hName := strings.ToLower(strings.TrimSpace(h.Name))
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

		if cand.CDNStatus == CDNStatusUnknown && weakCount > 0 {
			cand.CDNStatus = CDNLikely
		}
	}

	return nil
}

func parseTrailers(cand *Candidate, headers []hpack.HeaderField) error {
	cand.ResponseTrailersSeen = true
	for _, h := range headers {
		if len(h.Name) > 0 && h.Name[0] == ':' {
			return fmt.Errorf("pseudo-header %q found in trailers", h.Name)
		}
	}
	return nil
}

func ProbeH2(ctx context.Context, ip, sni string, ev DomainSource, cfg Config) (*Candidate, *ProbeError) {
	cand := &Candidate{
		IP:            ip,
		SNI:           sni,
		Evidence:      ev,
		DomainQuality: classifyDomainQuality(sni),
		CDNStatus:     CDNStatusUnknown,
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
		NextProtos:         []string{"h2"},
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
	if err := writeH2(uConn, buildClientSettingsFrame(), wTo); err != nil {
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
			return cand, &ProbeError{Stage: ProbeStageH2, Err: ctx.Err()}
		}
		n, err := uConn.Read(buf)
		if n > 0 {
			recvBuf.Write(buf[:n])
		}

		for recvBuf.Len() >= 9 {
			data := recvBuf.Bytes()
			length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
			if length > maxInboundFrameSize {
				return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("inbound frame exceeds limit: %d", length)}
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

			if expectingContinuation && frameType != FrameContinuation {
				return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("expected CONTINUATION frame")}
			}

			switch frameType {
			case FrameSettings, FrameGoAway:
				if streamID != 0 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("frame type %d must use stream 0, got %d", frameType, streamID)}
				}
			case FrameHeaders, FrameData, FrameRSTStream, FrameContinuation:
				if streamID == 0 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("frame type %d must use non-zero stream", frameType)}
				}
			}

			switch frameType {
			case FrameSettings:
				if length%6 != 0 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid SETTINGS length")}
				}
				if flags&FlagAck != 0 {
					if length != 0 {
						return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("SETTINGS ACK with non-zero payload")}
					}
					cand.H2SettingsAckReceived = true
					cand.SettingsAckCount++
					break
				}
				cand.SettingsFramesCount++
				seenSettings := make(map[uint16]bool)
				var prof PeerSettingsProfile
				if cand.H2SettingsReceived {
					prof = cand.LatestPeerSettings
				}
				for i := 0; i < int(length); i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					if seenSettings[id] {
						return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("duplicate SETTINGS identifier")}
					}
					seenSettings[id] = true
					switch id {
					case 1:
						prof.HeaderTableSize = val
						prof.HasHeaderTableSize = true
						decoder.SetMaxDynamicTableSize(val)
					case 2:
						return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("server sent SETTINGS_ENABLE_PUSH")}
					case 3:
						prof.MaxConcurrentStreams = val
						prof.HasMaxConcurrentStreams = true
					case 4:
						if val > 0x7fffffff {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid INITIAL_WINDOW_SIZE")}
						}
						prof.InitialWindowSize = val
						prof.HasInitialWindowSize = true
					case 5:
						if val < 16384 || val > 16777215 {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid MAX_FRAME_SIZE")}
						}
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
				if err := writeH2(uConn, buildH2Frame(FrameSettings, FlagAck, 0, nil), wTo); err != nil {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
				}
				cand.H2SettingsAckSent = true

			case FrameHeaders:
				if streamID == 1 {
					isTrailers := cand.EndStreamSeen
					if (flags & FlagEndStream) != 0 {
						cand.EndStreamSeen = true
					}
					actualPayload := payload
					padLen := 0
					if flags&FlagPadded != 0 {
						if len(actualPayload) < 1 {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("PADDED flag set but payload too short")}
						}
						padLen = int(actualPayload[0])
						actualPayload = actualPayload[1:]
					}
					if flags&FlagPriority != 0 {
						if len(actualPayload) < 5 {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("PRIORITY flag set but payload too short")}
						}
						actualPayload = actualPayload[5:]
					}
					if padLen > len(actualPayload) {
						return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("padding exceeds payload")}
					}
					actualPayload = actualPayload[:len(actualPayload)-padLen]

					headerBlocks.Write(actualPayload)
					if (flags & FlagEndHeaders) == 0 {
						expectingContinuation = true
						activeStreamID = streamID
					} else {
						expectingContinuation = false
						headers, err := decoder.DecodeFull(headerBlocks.Bytes())
						if err != nil {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
						}

						if !cand.ResponseHeadersParsed && !isTrailers {
							if err := parseResponseHeaders(cand, headers); err != nil {
								return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
							}
						} else {
							if err := parseTrailers(cand, headers); err != nil {
								return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
							}
						}
						headerBlocks.Reset()

						if cand.ResponseHeadersParsed && !cand.H2HeadersReceived {
							cand.Timings.H2Headers = time.Since(requestSent)
							cand.H2HeadersReceived = true
						}
					}
				}
			case FrameContinuation:
				if !expectingContinuation {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("unexpected CONTINUATION frame")}
				}
				if streamID != activeStreamID {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("CONTINUATION stream mismatch: got %d, want %d", streamID, activeStreamID)}
				}
				headerBlocks.Write(payload)
				if (flags & FlagEndHeaders) != 0 {
					expectingContinuation = false
					headers, err := decoder.DecodeFull(headerBlocks.Bytes())
					if err != nil {
						return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
					}

					if !cand.ResponseHeadersParsed {
						if err := parseResponseHeaders(cand, headers); err != nil {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
						}
					} else {
						if err := parseTrailers(cand, headers); err != nil {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
						}
					}
					headerBlocks.Reset()

					if cand.ResponseHeadersParsed && !cand.H2HeadersReceived {
						cand.Timings.H2Headers = time.Since(requestSent)
						cand.H2HeadersReceived = true
					}
				}
			case FrameData:
				if streamID == 1 {
					cand.H2DataFrames++
					if (flags & FlagEndStream) != 0 {
						cand.EndStreamSeen = true
					}
					actualPayload := payload
					padLen := 0
					if flags&FlagPadded != 0 {
						if len(actualPayload) < 1 {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("PADDED flag set on DATA but payload too short")}
						}
						padLen = int(actualPayload[0])
						actualPayload = actualPayload[1:]
					}
					if padLen > len(actualPayload) {
						return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("padding exceeds DATA payload")}
					}
					actualPayload = actualPayload[:len(actualPayload)-padLen]

					cand.BodyBytes += len(actualPayload)
					inc := length
					if inc > 0 {
						if err := writeH2(uConn, buildWindowUpdateFrame(1, inc), wTo); err != nil {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
						}
						if err := writeH2(uConn, buildWindowUpdateFrame(0, inc), wTo); err != nil {
							return cand, &ProbeError{Stage: ProbeStageH2, Err: err}
						}
					}
				}
			case FrameWindowUpdate:
				if length != 4 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid WINDOW_UPDATE length")}
				}
				increment := binary.BigEndian.Uint32(payload) & 0x7fffffff
				if increment == 0 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("WINDOW_UPDATE increment is zero")}
				}
			case FrameRSTStream:
				if length != 4 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid RST_STREAM length")}
				}
				if streamID == 1 {
					cand.StreamReset = true
					break ReadLoop
				}
			case FrameGoAway:
				if length < 8 {
					return cand, &ProbeError{Stage: ProbeStageH2, Err: fmt.Errorf("invalid GOAWAY length")}
				}
				cand.GoAwaySeen = true
			}
			if streamID == 1 && cand.EndStreamSeen && !expectingContinuation {
				break ReadLoop
			}
		}
		if err != nil {
			break
		}
	}
	if cand.HTTPStatus == 0 {
		return cand, &ProbeError{Stage: ProbeStageHeaders, Err: fmt.Errorf("no HTTP status code")}
	}
	if !cand.EndStreamSeen {
		return cand, &ProbeError{Stage: ProbeStageComplete, Err: fmt.Errorf("response did not reach END_STREAM")}
	}

	if cand.H2SettingsReceived && cand.H2HeadersReceived && cand.HTTPStatus >= 200 && cand.EndStreamSeen {
		cand.H2ProtocolConfirmed = true
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

	return cand.Score >= 0
}

func limitStr(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func RunPipeline(ctx context.Context, cfg Config, sampledIPs []string, scanRanges []ipRange, pool *DNSPool, asnDB, countryDB *geoip2.Reader) []Candidate {
	pipeStats := NewPipelineStats()
	pipeStats.mu.Lock()
	pipeStats.IPSampled = len(sampledIPs)
	pipeStats.mu.Unlock()

	discoveredDomains := make(map[string]DomainSource)
	var discoveredMu sync.Mutex

	fmt.Printf("[*] STAGE A: Active Discovery (PTR & Direct TLS)...\n")
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

			results := activeProbeIP(gCtxA, ip, pool, time.Duration(cfg.TLSTimeoutMs)*time.Millisecond, cfg.NoPTR, cfg.NoActiveTLS)
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

	if cfg.Mode == ModeDirect && cfg.DirectSNI != "" {
		sni := CleanDomain(cfg.DirectSNI)
		if sni != "" {
			for _, ip := range sampledIPs {
				key := ip + "\x00" + sni
				if _, loaded := pairSeen.LoadOrStore(key, true); !loaded {
					validPairs = append(validPairs, TargetPair{
						IP:       ip,
						SNI:      sni,
						Evidence: SourceSeed,
					})
				}
			}
		}
	}

	fmt.Printf("[*] STAGE D: DNS Validation (%d Domains)...\n", len(discoveredDomains))
	var uniqueResolvedIPs sync.Map
	var uniqueTargetIPs sync.Map

	gD, gCtxD := errgroup.WithContext(ctx)
	gD.SetLimit(cfg.Workers)
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

			ips, err := resolveIPv4DNSCrypt(gCtxD, pool, dom)

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
					parsedIP := net.ParseIP(resolvedIP)
					if parsedIP != nil {
						var asn uint
						var country string
						if asnDB != nil {
							if r, err := asnDB.ASN(parsedIP); err == nil {
								asn = uint(r.AutonomousSystemNumber)
							}
						}
						if countryDB != nil {
							if r, err := countryDB.Country(parsedIP); err == nil {
								country = r.Country.IsoCode
							}
						}
						if cfg.TargetASN != 0 && asn != cfg.TargetASN {
							pipeStats.mu.Lock()
							pipeStats.ASNFiltered++
							pipeStats.mu.Unlock()
							continue
						}
						if cfg.TargetCountry != "" && !strings.EqualFold(country, cfg.TargetCountry) {
							pipeStats.mu.Lock()
							pipeStats.CountryFiltered++
							pipeStats.mu.Unlock()
							continue
						}
					}

					uniqueTargetIPs.Store(resolvedIP, struct{}{})
					matched = true

					pipeStats.mu.Lock()
					pipeStats.DNSTargetRangeMatches++
					pipeStats.mu.Unlock()

					pairKey := resolvedIP + "\x00" + dom
					if _, loaded := pairSeen.LoadOrStore(pairKey, true); !loaded {
						var mu sync.Mutex
						mu.Lock()
						if len(validPairs) < LimitValidPairs {
							validPairs = append(validPairs, TargetPair{
								IP:       resolvedIP,
								SNI:      dom,
								Evidence: src,
							})
						}
						mu.Unlock()
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
	fmt.Printf("[+] Stage D Завершён. Подтверждено DNS-пар (IP+SNI): %d\n", pipeStats.DNSValidPairs)
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
			if pErr != nil && pErr.Stage == ProbeStageTLSValidation {
				if strings.Contains(pErr.Err.Error(), "no peer certificates") {
					pipeStats.NoPeerCertificates++
				} else {
					pipeStats.TLSValidationFailures++
				}
			}
			if cand != nil && cand.H2HeadersReceived {
				pipeStats.H2HeadersOK++
			}
			if cand != nil && cand.EndStreamSeen {
				pipeStats.EndStreamOK++
			}
			pipeStats.mu.Unlock()

			if pErr != nil {
				return nil
			}

			if parsedIP := net.ParseIP(cand.IP); parsedIP != nil {
				if asnDB != nil {
					if r, err := asnDB.ASN(parsedIP); err == nil {
						cand.ASN = uint(r.AutonomousSystemNumber)
					}
				}
				if countryDB != nil {
					if r, err := countryDB.Country(parsedIP); err == nil {
						cand.Country = r.Country.IsoCode
					}
				}
			}

			if validateAndEnrich(cand, cfg, pipeStats) {
				candMu.Lock()
				candidates = append(candidates, *cand)
				candMu.Unlock()
			}
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
		clusteredCandidates = append(clusteredCandidates, cluster[0])
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
	fmt.Printf("[*] Target Range IP Matches:   %d\n", s.DNSTargetRangeMatches)
	fmt.Printf("[*] Подтверждено DNS-пар:      %d\n\n", s.DNSValidPairs)

	fmt.Printf("[*] Успешных TCP соединений:   %d\n", s.TCPConnected)
	fmt.Printf("[*] Успешных TLS хэндшейков:   %d\n", s.TLSHandshake)
	fmt.Printf("[*] С откликом H2 Headers:     %d\n", s.H2HeadersOK)
	fmt.Printf("[*] Финальных IP-кластеров:    %d\n", len(clusteredCandidates))
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
	flag.IntVar(&cfg.MaxIPs, "max-ips", 0, "Limit for IP sampling (0 = default 1024, -1 = up to hard safety limit 262144)")
	flag.IntVar(&cfg.TCPTimeoutMs, "tcp-timeout", 2000, "TCP timeout ms")
	flag.IntVar(&cfg.TLSTimeoutMs, "tls-timeout", 2000, "TLS timeout ms")
	flag.IntVar(&cfg.H2ReadTimeoutMs, "h2-read", 3000, "H2 Read timeout ms")
	flag.IntVar(&cfg.H2WriteTimeoutMs, "h2-write", 2000, "H2 Write timeout ms")
	flag.Int64Var(&cfg.Seed, "seed", time.Now().UnixNano(), "Random seed")
	flag.StringVar(&cfg.TargetCountry, "c", "", "Hard Filter: Target Country Code")
	flag.UintVar(&cfg.TargetASN, "asn", 0, "Hard Filter: Target ASN constraint")
	flag.StringVar(&cfg.TargetIP, "vps-ip", "", "IP сервера для поиска сети (запуск с ПК)")
	flag.StringVar(&cfg.DirectSNI, "sni", "", "Fallback SNI for Direct mode")
	flag.BoolVar(&cfg.ScanEntireASN, "scan-all-asn", false, "Scan all ASN prefixes")
	flag.StringVar(&domainsStr, "domains", "", "Comma-separated seed domains for OSINT")
	flag.StringVar(&cfg.GeoIPPath, "geoip", "GeoLite2-Country.mmdb", "Path to Country DB")
	flag.StringVar(&cfg.ASNPath, "asn-db", "GeoLite2-ASN.mmdb", "Path to ASN DB")

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
	if cfg.MaxIPs == -1 {
		fmt.Printf("[!] ВНИМАНИЕ: Выбран режим полного сканирования (-1 = до %d адресов).\n", LimitMaxIPs)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := ensureDB(cfg.ASNPath, "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"); err != nil {
		log.Fatalf("[-] Ошибка загрузки базы ASN (%s): %v", cfg.ASNPath, err)
	}
	if err := ensureDB(cfg.GeoIPPath, "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"); err != nil {
		log.Fatalf("[-] Ошибка загрузки базы Country (%s): %v", cfg.GeoIPPath, err)
	}

	var asnDB, countryDB *geoip2.Reader
	var err error
	if asnDB, err = geoip2.Open(cfg.ASNPath); err != nil {
		log.Fatal("[-] Failed to open ASN DB")
	}
	defer asnDB.Close()

	if countryDB, err = geoip2.Open(cfg.GeoIPPath); err != nil {
		log.Fatal("[-] Failed to open GeoIP DB")
	}
	defer countryDB.Close()

	dnsCtx, dnsCancel := context.WithTimeout(ctx, 60*time.Second)
	defer dnsCancel()
	fmt.Println("[DNS] Загрузка публичного DNSCrypt pool...")
	stamps, err := loadResolverStamps(dnsCtx)
	if err != nil {
		log.Fatalf("[-] DNSCrypt list: %v", err)
	}

	dnsPool := buildDNSPool(dnsCtx, stamps)
	dnsPool.mu.RLock()
	poolSize := len(dnsPool.resolvers)
	dnsPool.mu.RUnlock()

	if poolSize < 5 {
		log.Fatalf("[-] Слишком мало рабочих DNSCrypt resolver'ов: %d", poolSize)
	}
	fmt.Printf("[+] Рабочий DNSCrypt pool: %d resolver'ов\n", poolSize)

	var vpsQueryIP, localPrefix string

	if cfg.Mode == ModeAuto {
		ip, err := getPublicIP(cfg.TargetIP)
		if err != nil {
			log.Fatalf("[-] Ошибка получения публичного IP: %v\n", err)
		}
		vpsQueryIP = ip

		parsedIP := net.ParseIP(vpsQueryIP)
		if cfg.TargetASN == 0 {
			if r, err := asnDB.ASN(parsedIP); err == nil {
				cfg.TargetASN = uint(r.AutonomousSystemNumber)
			} else {
				log.Fatal("[-] Не удалось определить ASN по GeoIP")
			}
		}
		if cfg.TargetCountry == "" {
			if r, err := countryDB.Country(parsedIP); err == nil {
				cfg.TargetCountry = r.Country.IsoCode
			} else {
				log.Fatal("[-] Не удалось определить Country по GeoIP")
			}
		}
	}

	var results []Candidate

	if cfg.Mode == ModeAuto {
		cidrs, err := fetchASNCIDRs(cfg.TargetASN)
		if err != nil || len(cidrs) == 0 {
			log.Fatalf("[-] Failed to fetch CIDRs for AS%d", cfg.TargetASN)
		}
		vpsIPObj := net.ParseIP(vpsQueryIP)
		for _, c := range cidrs {
			_, ipnet, _ := net.ParseCIDR(c)
			if ipnet != nil && ipnet.Contains(vpsIPObj) {
				localPrefix = c
				break
			}
		}
		var samplingCIDRs []string
		if !cfg.ScanEntireASN {
			if localPrefix == "" {
				log.Fatal("[-] Target IP is not present in ASN announced prefixes. Use --scan-all-asn.")
			}
			samplingCIDRs = []string{localPrefix}
		} else {
			samplingCIDRs = cidrs
		}

		samplingRanges := MergeCIDRs(samplingCIDRs)
		sampledIPs := SampleIPs(samplingRanges, cfg.MaxIPs, cfg.Seed)
		dnsRanges := MergeCIDRs(cidrs)

		fmt.Printf("[*] Целевой IP:             %s\n", vpsQueryIP)
		fmt.Printf("[*] Announcing ASN:         AS%d\n", cfg.TargetASN)
		if !cfg.ScanEntireASN {
			fmt.Printf("[*] Фокус на IPv4 prefix:    %s (DNS-валидация по всем %d префиксам ASN)\n", localPrefix, len(cidrs))
		} else {
			fmt.Printf("[*] Фокус на все префиксы:   %d подсетей ASN\n", len(cidrs))
		}
		fmt.Printf("[*] Страна сервера:          %s (MaxMind GeoIP)\n", cfg.TargetCountry)
		fmt.Printf("[*] Подготовлено %d IP адресов для OSINT-сэмплинга. Запуск...\n\n", len(sampledIPs))

		results = RunPipeline(ctx, cfg, sampledIPs, dnsRanges, dnsPool, asnDB, countryDB)

	} else if cfg.Mode == ModeDirect {
		merged := MergeCIDRs(cfg.CIDRs)
		sampledIPs := SampleIPs(merged, cfg.MaxIPs, cfg.Seed)
		fmt.Printf("[*] Direct Mode: Подготовлено %d IP адресов. Запуск...\n", len(sampledIPs))
		results = RunPipeline(ctx, cfg, sampledIPs, merged, dnsPool, asnDB, countryDB)
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
