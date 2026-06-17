
package main

import (
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
		err = insertThreat(db, threat)
		if err != nil {
			log.Printf("Insert error: %v\n", err)
			continue
		}
		newCount++
	}
	return newCount
}
