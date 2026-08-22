package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ================= НАСТРОЙКИ =================
const ConnectTimeout = 1200 * time.Millisecond
const MaxHostsPer24 = 254
const MaxSampled24 = 4

var bannedTLDs = map[string]bool{
	"crl": true, "ocsp": true, "der": true, "crt": true, "cer": true, "pem": true,
	"arpa": true, "local": true, "internal": true, "invalid": true, "example": true, "test": true, "localhost": true,
}

// ================= СТРУКТУРЫ =================
type Target struct {
	IP      string
	Domains []string
}

// ================= BGP И GEOIP ХЕЛПЕРЫ =================
func getPublicIP() string {
	urls := []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, u := range urls {
		resp, err := client.Get(u)
		if err == nil {
			defer resp.Body.Close()
			ipBytes, _ := io.ReadAll(resp.Body)
			ipStr := strings.TrimSpace(string(ipBytes))
			if net.ParseIP(ipStr) != nil {
				return ipStr
			}
		}
	}
	return "127.0.0.1"
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
	asn, prefix := "", ""
	client := &http.Client{Timeout: 6 * time.Second}
	
	// 1. Пробуем через RIPE
	resp, err := client.Get(fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", ip))
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			Data struct {
				ASNs   []interface{} `json:"asns"`
				Prefix string        `json:"prefix"`
			} `json:"data"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) == nil {
			if len(result.Data.ASNs) > 0 {
				asn = fmt.Sprintf("%v", result.Data.ASNs[0])
				if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
					asn = "AS" + asn
				}
			}
			prefix = result.Data.Prefix
		}
	}

	// 2. Резервный поиск ASN через ip-api
	if asn == "" {
		resp2, err2 := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=as", ip))
		if err2 == nil {
			defer resp2.Body.Close()
			var res2 struct {
				AS string `json:"as"`
			}
			if json.NewDecoder(resp2.Body).Decode(&res2) == nil {
				parts := strings.Split(res2.AS, " ")
				if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
					asn = parts[0]
				}
			}
		}
	}

	// 3. Резервный префикс (жестко берем /24 от IP), если RIPE ничего не вернул
	if prefix == "" {
		parsedIP := net.ParseIP(ip).To4()
		if parsedIP != nil {
			prefix = fmt.Sprintf("%d.%d.%d.0/24", parsedIP[0], parsedIP[1], parsedIP[2])
		}
	}

	return asn, prefix
}

func getPrefixes(asn string) []string {
	if asn == "" {
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
		if !strings.Contains(p.Prefix, ":") { // Только IPv4
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

// ================= ГЕНЕРАТОР IP =================
func generateIPs(prefixes []string, maxIPs int) []string {
	var ips []string
	seen := make(map[string]bool)

	for _, pStr := range prefixes {
		if maxIPs > 0 && len(ips) >= maxIPs {
			break
		}
		ip, ipnet, err := net.ParseCIDR(pStr)
		if err != nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		if ones >= 24 {
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
					if count >= MaxHostsPer24 {
						break
					}
				}
			}
		} else {
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
					if count >= (MaxHostsPer24 * MaxSampled24) {
						break
					}
				}
			}
		}
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ================= ВАЛИДАЦИЯ ДОМЕНОВ И OSINT =================
func cleanDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "*.")))
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return ""
	}
	tld := parts[len(parts)-1]
	matched, _ := regexp.MatchString(`^[a-z]{2,24}$`, tld)
	if !matched || bannedTLDs[tld] {
		return ""
	}
	if strings.ContainsAny(d, " \t\r\n/\\:*?\"'<>|#%&={}~`!@$^()+[]") {
		return ""
	}
	return d
}

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
		json.NewDecoder(resp.Body).Decode(&res)
		for _, r := range res.PassiveDNS {
			if d := cleanDomain(r.Hostname); d != "" {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func getPTR(ip string) []string {
	names, err := net.LookupAddr(ip)
	var res []string
	if err == nil {
		for _, n := range names {
			if d := cleanDomain(strings.TrimSuffix(n, ".")); d != "" {
				res = append(res, d)
			}
		}
	}
	return res
}

// ================= UTLS И ПРОБИНГ =================
func checkTLS(ip, sni string) (string, []string) {
	dialer := &net.Dialer{Timeout: ConnectTimeout}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return "DEAD", nil
	}
	defer conn.Close()

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto) 

	uConn.SetDeadline(time.Now().Add(ConnectTimeout))
	err = uConn.Handshake()

	if err != nil {
		return "SSL_ERROR", nil
	}

	var doms []string
	certs := uConn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		for _, d := range certs[0].DNSNames {
			if cd := cleanDomain(d); cd != "" {
				doms = append(doms, cd)
			}
		}
		if cd := cleanDomain(certs[0].Subject.CommonName); cd != "" {
			doms = append(doms, cd)
		}
	}
	return "OK", doms
}

func probeIP(ip string) (string, []string) {
	status, doms := checkTLS(ip, ip)

	if status == "DEAD" {
		return ip, nil
	}

	domSet := make(map[string]bool)
	for _, d := range doms {
		domSet[d] = true
	}

	if len(domSet) > 15 {
		return ip, nil // Дроп CDN / Shared
	}

	if status == "SSL_ERROR" || len(domSet) == 0 {
		ptrs := getPTR(ip)
		for _, ptr := range ptrs {
			stat, cDoms := checkTLS(ip, ptr)
			if stat == "OK" {
				for _, d := range cDoms {
					domSet[d] = true
				}
			}
		}

		if len(domSet) == 0 {
			osints := getOSINTDomains(ip)
			for _, osint := range osints {
				stat, cDoms := checkTLS(ip, osint)
				if stat == "OK" {
					for _, d := range cDoms {
						domSet[d] = true
					}
					break
				}
			}
		}
	}

	var finalDoms []string
	for d := range domSet {
		// Главное условие фильтрации: SNI не должен совпадать с IP
		if d != ip {
			finalDoms = append(finalDoms, d)
		}
		if len(finalDoms) >= 5 {
			break
		}
	}
	return ip, finalDoms
}

// ================= MAIN =================
func main() {
	workers := flag.Int("w", 500, "Количество горутин (concurrency)")
	maxIPs := flag.Int("max-ips", 0, "Лимит IP для скана")
	debugIP := flag.String("debug-ip", "", "Проверить один IP")
	vpsIP := flag.String("vps-ip", "", "IP сервера для поиска сети (запуск с ПК)")
	countryFlag := flag.String("c", "", "Принудительно код страны (например, RU, US, NL)")
	allFlag := flag.Bool("all", false, "Сканировать все подсети ASN без гео-фильтра")
	flag.Parse()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("      RIPE SNI SCANNER (Только сбор несовпадающих SNI)")
	fmt.Println(strings.Repeat("=", 80))

	if *debugIP != "" {
		fmt.Printf("\n[*] Отладка IP: %s\n", *debugIP)
		ip, doms := probeIP(*debugIP)
		fmt.Printf("[+] Найденные несовпадающие SNI: %v\n", doms)
		return
	}

	var myIP string
	if *vpsIP != "" {
		myIP = *vpsIP
		fmt.Printf("[*] Используем указанный IP VPS: %s\n", myIP)
	} else {
		myIP = getPublicIP()
		fmt.Printf("[*] Внешний IP (Авто):         %s\n", myIP)
	}

	asn, prefix := getASNAndPrefix(myIP)
	fmt.Printf("[*] Announcing ASN:          %s (Локальный префикс: %s)\n", asn, prefix)
	fmt.Printf("[*] Параллелизм:             %d горутин\n", *workers)

	var country string
	if *allFlag {
		fmt.Println("[*] Фильтрация по гео:       Отключена (флаг --all)")
	} else if *countryFlag != "" {
		country = strings.ToUpper(*countryFlag)
		fmt.Printf("[*] Страна сервера:          %s (задана вручную)\n", country)
	} else {
		country = getCountry(myIP)
		fmt.Printf("[*] Страна сервера:          %s (GeoIP)\n", country)
	}

	allPrefixes := getPrefixes(asn)
	// Важно: если API не выдало подсетей, используем сгенерированный фолбэк-префикс
	if len(allPrefixes) == 0 && prefix != "" {
		allPrefixes = []string{prefix}
	}

	var targetPrefixes []string
	if *allFlag || country == "" {
		targetPrefixes = allPrefixes
	} else {
		targetPrefixes = filterPrefixesByCountry(allPrefixes, country)
		
		foundLocal := false
		for _, p := range targetPrefixes {
			if p == prefix {
				foundLocal = true
				break
			}
		}
		if !foundLocal && prefix != "" {
			targetPrefixes = append([]string{prefix}, targetPrefixes...)
		}
	}

	fmt.Printf("[*] Подсетей для скана:      %d (из %d)\n", len(targetPrefixes), len(allPrefixes))

	ips := generateIPs(targetPrefixes, *maxIPs)
	totalIPs := len(ips)
	fmt.Printf("[*] Подготовлено %d IP адресов. Запуск...\n", totalIPs)

	if totalIPs == 0 {
		fmt.Println("[-] Нет IP-адресов для сканирования.")
		return
	}

	jobs := make(chan string, totalIPs)
	results := make(chan Target, totalIPs)
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				_, doms := probeIP(ip)
				if len(doms) > 0 {
					results <- Target{IP: ip, Domains: doms}
				}
			}
		}()
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(results)

	var targets []Target
	for t := range results {
		targets = append(targets, t)
	}

	fmt.Printf("\n[+] Сканирование завершено. Найдено целей: %d\n\n", len(targets))
	if len(targets) == 0 {
		fmt.Println("[-] Подходящих целей не обнаружено.")
		return
	}

	fmt.Printf("%-15s | %s\n", "IP адрес", "Домены (SNI)")
	fmt.Println(strings.Repeat("-", 80))
	for _, t := range targets {
		fmt.Printf("%-15s | %s\n", t.IP, strings.Join(t.Domains, ", "))
	}
}
