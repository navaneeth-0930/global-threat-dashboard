package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type DashboardData struct {
	Total   int            `json:"total"`
	ByType  map[string]int `json:"by_type"`
	Latest  time.Time      `json:"latest"`
	Recent  []Threat       `json:"recent"`
}

func main() {
	db := initDB()
	defer db.Close()

	go fetchURLHaus(db)

	// Dashboard UI
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, dashboardHTML)
	})

	// JSON API for the dashboard to call
	http.HandleFunc("/api/threats/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		data := DashboardData{ByType: make(map[string]int)}

		// Total count
		db.Get(&data.Total, `SELECT COUNT(*) FROM threats`)

		// Count by threat type
		rows, _ := db.Query(`
			SELECT threat_type, COUNT(*) as cnt
			FROM threats
			GROUP BY threat_type
			ORDER BY cnt DESC
		`)
		defer rows.Close()
		for rows.Next() {
			var ttype string
			var cnt int
			rows.Scan(&ttype, &cnt)
			data.ByType[ttype] = cnt
		}

		// Latest seen_at
		db.Get(&data.Latest, `SELECT MAX(seen_at) FROM threats`)

		// 50 most recent for the live feed
		db.Select(&data.Recent, `
			SELECT * FROM threats
			ORDER BY seen_at DESC
			LIMIT 50
		`)

		json.NewEncoder(w).Encode(data)
	})

	log.Println("🚀 Dashboard live at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}