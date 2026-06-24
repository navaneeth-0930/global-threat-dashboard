package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

const URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/csv_recent/"

func fetchURLHaus(db *sqlx.DB) {
	for {
		log.Println("Fetching URLHaus feed...")
		resp, err := http.Get(URLHAUS_FEED)
		if err != nil {
			log.Printf("URLHaus fetch error: %v - retrying in 5 min\n", err)
			time.Sleep(5 * time.Minute)
			continue
		}
		newCount := parseURLHausCSV(db, resp.Body)
		resp.Body.Close()
		log.Printf("URLHaus: inserted %d new threats\n", newCount)
		time.Sleep(5 * time.Minute)
	}
}

func parseURLHausCSV(db *sqlx.DB, body io.Reader) int {
	reader := csv.NewReader(body)
	reader.Comment = '#'
	reader.LazyQuotes = true
	newCount := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("CSV parse warning: %v\n", err)
			continue
		}
		if len(row) < 6 {
			continue
		}
		urlValue := strings.TrimSpace(row[2])
		threatType := strings.TrimSpace(row[5])
		dateAdded := strings.TrimSpace(row[1])
		if urlValue == "" || urlValue == "url" {
			continue
		}
		seenAt, err := time.Parse("2006-01-02 15:04:05", dateAdded)
		if err != nil {
			seenAt = time.Now()
		}
		threat := Threat{
			FeedSource: "URLHaus",
			ThreatType: threatType,
			Indicator:  urlValue,
			RawData:    strings.Join(row, "|"),
			SeenAt:     seenAt,
		}
		wasInserted, err := insertThreat(db, threat)
		if err != nil {
			log.Printf("Insert error: %v\n", err)
			continue
		}
		if wasInserted {
			newCount++
		}
	}
	return newCount

}

const OPENPHISH_FEED = "https://openphish.com/feed.txt"

func fetchOpenPhish(db *sqlx.DB) {
	for {
		log.Println("🎣 Fetching OpenPhish feed...")
		resp, err := http.Get(OPENPHISH_FEED)
		if err != nil {
			log.Printf("❌ OpenPhish fetch error: %v — retrying in 5 min\n", err)
			time.Sleep(5 * time.Minute)
			continue
		}

		newCount := parseOpenPhishText(db, resp.Body)
		resp.Body.Close()
		log.Printf("✅ OpenPhish: inserted %d new threats\n", newCount)

		time.Sleep(5 * time.Minute)
	}
}

// OpenPhish's format is the simplest possible: one URL per line, nothing else.
// We use bufio.Scanner instead of encoding/csv here, since there's no
// columns or commas to parse — just raw lines of text.
func parseOpenPhishText(db *sqlx.DB, body io.Reader) int {
	scanner := bufio.NewScanner(body)
	newCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue // skip blank lines
		}

		threat := Threat{
			FeedSource: "OpenPhish",
			ThreatType: "phishing",
			Indicator:  line,
			RawData:    line,
			SeenAt:     time.Now(), // OpenPhish doesn't give us a timestamp per URL, so we use "now"
		}

		wasInserted, err := insertThreat(db, threat)
		if err != nil {
			log.Printf("Insert error: %v\n", err)
			continue
		}
		if wasInserted {
			newCount++
		}
	}

	return newCount
}

const FEODO_FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

func fetchFeodoTracker(db *sqlx.DB) {
	for {
		log.Println("🕵️ Fetching Feodo Tracker feed...")
		resp, err := http.Get(FEODO_FEED)
		if err != nil {
			log.Printf("❌ Feodo fetch error: %v — retrying in 5 min\n", err)
			time.Sleep(5 * time.Minute)
			continue
		}

		newCount := parseFeodoCSV(db, resp.Body)
		resp.Body.Close()
		log.Printf("✅ Feodo Tracker: inserted %d new threats\n", newCount)

		time.Sleep(5 * time.Minute)
	}
}

// Feodo Tracker's CSV columns (after comment lines):
// 0: first_seen, 1: dst_ip, 2: dst_port, 3: c2_status, 4: last_online, 5: malware
func parseFeodoCSV(db *sqlx.DB, body io.Reader) int {
	reader := csv.NewReader(body)
	reader.Comment = '#'
	reader.LazyQuotes = true

	newCount := 0

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("CSV parse warning: %v\n", err)
			continue
		}
		if len(row) < 6 {
			continue
		}

		firstSeen := strings.TrimSpace(row[0])
		ip := strings.TrimSpace(row[1])
		port := strings.TrimSpace(row[2])
		malwareFamily := strings.TrimSpace(row[5])

		if ip == "" || ip == "dst_ip" {
			continue
		}

		// We combine ip:port to form one indicator string, consistent
		// with how URLHaus indicators sometimes look (e.g. "1.2.3.4:443")
		indicator := ip + ":" + port

		seenAt, err := time.Parse("2006-01-02 15:04:05", firstSeen)
		if err != nil {
			seenAt = time.Now()
		}

		// Skip stale entries — anything first seen more than 60 days ago is
		// probably no longer meaningfully "active," even if Feodo Tracker
		// still lists it. This keeps our dashboard focused on CURRENT threats.
		const maxAge = 60 * 24 * time.Hour
		if time.Since(seenAt) > maxAge {
			continue
		}

		threat := Threat{
			FeedSource: "FeodoTracker",
			ThreatType: malwareFamily,
			Indicator:  indicator,
			RawData:    strings.Join(row, "|"),
			SeenAt:     seenAt,
		}

		wasInserted, err := insertThreat(db, threat)
		if err != nil {
			log.Printf("Insert error: %v\n", err)
			continue
		}
		if wasInserted {
			newCount++
		}
	}

	return newCount
}

const THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

func fetchThreatFox(db *sqlx.DB) {
	apiKey := os.Getenv("THREATFOX_KEY")
	if apiKey == "" {
		log.Println("⚠️ THREATFOX_KEY not set — skipping ThreatFox feed entirely")
		return // exit the goroutine early; no point retrying forever without a key
	}

	for {
		log.Println("🦊 Fetching ThreatFox feed...")

		// Build the JSON body we want to send: { "query": "get_iocs", "days": 1 }
		// This asks ThreatFox for IOCs added in the last 1 day.
		requestBody, _ := json.Marshal(map[string]interface{}{
			"query": "get_iocs",
			"days":  1,
		})

		// http.NewRequest lets us build a request manually, since http.Get()
		// only knows how to do simple GET requests with no custom headers/body.
		// bytes.NewBuffer wraps our []byte JSON into something the http
		// library knows how to stream as a request body.
		req, err := http.NewRequest("POST", THREATFOX_URL, bytes.NewBuffer(requestBody))
		if err != nil {
			log.Printf("❌ ThreatFox request build error: %v\n", err)
			time.Sleep(5 * time.Minute)
			continue
		}

		// Headers are metadata sent alongside the request. This is how we
		// authenticate — same idea as showing ID before being let into a building.
		req.Header.Set("Auth-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		// http.DefaultClient.Do() actually sends the request we built.
		// (http.Get() was secretly just a shortcut for this same thing.)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("❌ ThreatFox fetch error: %v — retrying in 5 min\n", err)
			time.Sleep(5 * time.Minute)
			continue
		}

		newCount := parseThreatFoxJSON(db, resp.Body)
		resp.Body.Close()
		log.Printf("✅ ThreatFox: inserted %d new threats\n", newCount)

		time.Sleep(5 * time.Minute)
	}
}

// ThreatFoxResponse mirrors the top-level shape ThreatFox sends back
type ThreatFoxResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        []ThreatFoxItem `json:"data"`
}

// ThreatFoxItem mirrors one single IOC entry inside "data"
type ThreatFoxItem struct {
	IOC        string `json:"ioc"`
	ThreatType string `json:"threat_type"`       // e.g. "botnet_cc", "payload_delivery"
	IOCType    string `json:"ioc_type"`          // e.g. "ip:port", "url", "domain"
	Malware    string `json:"malware_printable"` // human-readable malware family name
	FirstSeen  string `json:"first_seen_utc"`
}

func parseThreatFoxJSON(db *sqlx.DB, body io.Reader) int {
	var response ThreatFoxResponse

	if err := json.NewDecoder(body).Decode(&response); err != nil {
		log.Printf("ThreatFox JSON parse error: %v\n", err)
		return 0
	}

	if response.QueryStatus != "ok" {
		log.Printf("ThreatFox query did not succeed: %s\n", response.QueryStatus)
		return 0
	}

	newCount := 0

	for _, item := range response.Data {
		if item.IOC == "" {
			continue
		}

		seenAt, err := time.Parse("2006-01-02 15:04:05", item.FirstSeen)
		if err != nil {
			seenAt = time.Now()
		}

		threat := Threat{
			FeedSource: "ThreatFox",
			ThreatType: item.Malware, // we use the malware family name as the "type" shown in our table
			Indicator:  item.IOC,
			RawData:    item.ThreatType + "|" + item.IOCType,
			SeenAt:     seenAt,
		}

		wasInserted, err := insertThreat(db, threat)
		if err != nil {
			log.Printf("Insert error: %v\n", err)
			continue
		}
		if wasInserted {
			newCount++
		}
	}

	return newCount
}
