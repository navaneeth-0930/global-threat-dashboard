package main

import (
	"bufio"
	"encoding/csv"
	"io"
	"log"
	"net/http"
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
