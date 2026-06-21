package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// A regular expression that matches a plain IPv4 address like "110.36.65.9"
// Regex is a pattern-matching language for text — think of it as a search
// query for shapes of text rather than exact words.
// \d means "any digit", {1,3} means "1 to 3 of them", \. means a literal dot.
var ipv4Pattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// extractIP pulls just the IP address out of a raw indicator string.
// Handles cases like:
//
//	"http://110.36.65.9:36400/bin.sh"  -> "110.36.65.9"
//	"110.36.65.9"                       -> "110.36.65.9"
//	"https://evil.xyz/path"             -> "" (not an IP, we skip it)
func extractIP(indicator string) string {
	// url.Parse breaks a URL into its pieces: scheme, host, path, etc.
	// This is the same idea as the URL object in JavaScript: new URL(str).hostname
	parsed, err := url.Parse(indicator)
	host := ""

	if err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else {
		// If it wasn't a full URL (no http:// prefix), treat the whole
		// string as the host, but still strip off a port if present
		host = strings.Split(indicator, "/")[0]
		host = strings.Split(host, ":")[0]
	}

	if ipv4Pattern.MatchString(host) {
		return host
	}
	return "" // not an IP — we skip domains for now
}

// GeoResult mirrors the JSON shape that ip-api.com sends back
type GeoResult struct {
	Status  string  `json:"status"`
	Lat     float64 `json:"lat"`
	Lng     float64 `json:"lon"`
	Country string  `json:"country"`
	City    string  `json:"city"`
}

// lookupIP checks our local cache first. Only if the IP is genuinely new
// do we call the external API — this is the rate-limit protection.
func lookupIP(db *sqlx.DB, ip string) (*GeoResult, error) {
	// 1. Check the cache first
	var cached GeoResult
	err := db.Get(&cached, `SELECT lat, lng, country, city FROM geo_cache WHERE ip = ?`, ip)
	if err == nil {
		// Found it locally — no need to call the internet at all
		return &cached, nil
	}

	// 2. Not cached — call the free ip-api.com service
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GeoResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "success" {
		return nil, nil // some IPs are private/reserved and can't be located
	}

	// 3. Save it to our cache so we NEVER look this IP up again
	_, err = db.Exec(`
		INSERT OR REPLACE INTO geo_cache (ip, lat, lng, country, city)
		VALUES (?, ?, ?, ?, ?)
	`, ip, result.Lat, result.Lng, result.Country, result.City)
	if err != nil {
		log.Printf("Failed to cache geo result for %s: %v\n", ip, err)
	}

	return &result, nil
}

// geolocateNewThreats runs periodically, finds threats whose IP we haven't
// looked up yet, and processes them slowly enough to respect the free API's
// rate limit (we sleep between each call).
func geolocateNewThreats(db *sqlx.DB) {
	for {
		var indicators []string
		// LEFT JOIN + WHERE geo_cache.ip IS NULL is a classic SQL pattern
		// meaning: "give me threats that DON'T have a matching geo_cache row yet"
		err := db.Select(&indicators, `
			SELECT DISTINCT t.indicator
			FROM threats t
			LIMIT 500
		`)
		if err != nil {
			log.Printf("geolocate query error: %v\n", err)
			time.Sleep(1 * time.Minute)
			continue
		}

		processedCount := 0
		for _, indicator := range indicators {
			ip := extractIP(indicator)
			if ip == "" {
				continue // not an IP-based indicator, skip
			}

			// Skip if already cached (avoids wasting time re-checking)
			var exists int
			db.Get(&exists, `SELECT COUNT(*) FROM geo_cache WHERE ip = ?`, ip)
			if exists > 0 {
				continue
			}

			_, err := lookupIP(db, ip)
			if err != nil {
				log.Printf("geo lookup failed for %s: %v\n", ip, err)
			}
			processedCount++

			// Respect the free tier's rate limit: roughly 45 requests/min
			// means about 1 request every 1.3 seconds. We'll be conservative.
			time.Sleep(1500 * time.Millisecond)
		}

		log.Printf("🌍 Geolocation pass complete — processed %d new IPs\n", processedCount)
		time.Sleep(5 * time.Minute) // wait before scanning for new threats again
	}
}
