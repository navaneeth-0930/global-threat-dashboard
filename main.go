package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type DashboardData struct {
	Total  int            `json:"total"`
	ByType map[string]int `json:"by_type"`
	Latest time.Time      `json:"latest"`
	Recent []Threat       `json:"recent"`
}

func main() {
	db := initDB()
	defer db.Close()

	go fetchURLHaus(db)
	go fetchOpenPhish(db)
	go fetchFeodoTracker(db)
	go geolocateNewThreats(db)

	// Dashboard UI
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, dashboardHTML)
	})

	// JSON API for the dashboard to call
	// TEMPORARY debug route — lets us see what's inside geo_cache
	// without needing the sqlite3 command line tool. We'll delete
	// this once we trust the pipeline is working.
	http.HandleFunc("/api/debug/geocache", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		type GeoCacheRow struct {
			IP      string  `db:"ip" json:"ip"`
			Lat     float64 `db:"lat" json:"lat"`
			Lng     float64 `db:"lng" json:"lng"`
			Country string  `db:"country" json:"country"`
			City    string  `db:"city" json:"city"`
		}

		var rows []GeoCacheRow
		err := db.Select(&rows, `SELECT ip, lat, lng, country, city FROM geo_cache LIMIT 20`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": len(rows),
			"rows":  rows,
		})
	})

	http.HandleFunc("/api/arcs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// This SQL joins our threats table to our geo_cache table.
		// Think of it like: "for every threat, look up its matching
		// geo_cache row using the IP buried inside the indicator text."
		// We can't easily extract the IP in pure SQL, so instead we'll
		// pull ALL geo_cache rows directly — every row in geo_cache
		// already represents one real threat origin we successfully located.
		type RawGeo struct {
			Lat     float64 `db:"lat"`
			Lng     float64 `db:"lng"`
			Country string  `db:"country"`
			City    string  `db:"city"`
		}

		var geos []RawGeo
		err := db.Select(&geos, `SELECT lat, lng, country, city FROM geo_cache`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// Group by city so we don't draw 50 overlapping arcs from the same place.
		// This map acts like a JS object: { "Harbin,China": 4, "Bangkok,Thailand": 2 }
		grouped := make(map[string]*ArcData)

		for _, g := range geos {
			key := g.City + "," + g.Country

			if existing, found := grouped[key]; found {
				existing.Count++
			} else {
				grouped[key] = &ArcData{
					StartLat: g.Lat,
					StartLng: g.Lng,
					EndLat:   DASHBOARD_LAT,
					EndLng:   DASHBOARD_LNG,
					Country:  g.Country,
					City:     g.City,
					Count:    1,
				}
			}
		}

		// Convert the map back into a plain slice (array), since JSON
		// arrays are easier for the frontend to loop over than map objects
		arcs := make([]ArcData, 0, len(grouped))
		for _, arc := range grouped {
			arcs = append(arcs, *arc)
		}

		json.NewEncoder(w).Encode(arcs)
	})

	http.HandleFunc("/api/threats/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Read the "source" query parameter from the URL, e.g. ?source=OpenPhish
		// r.URL.Query().Get(...) returns an empty string if the parameter wasn't provided
		sourceFilter := r.URL.Query().Get("source")

		data := DashboardData{ByType: make(map[string]int)}

		db.Get(&data.Total, `SELECT COUNT(*) FROM threats`)

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

		db.Get(&data.Latest, `SELECT MAX(seen_at) FROM threats`)

		// If a source filter was given, only fetch threats from that source.
		// Otherwise (sourceFilter == ""), fetch everything, same as before.
		if sourceFilter != "" {
			db.Select(&data.Recent, `
            SELECT * FROM threats
            WHERE feed_source = ?
            ORDER BY seen_at DESC
            LIMIT 50
        `, sourceFilter)
		} else {
			db.Select(&data.Recent, `
            SELECT * FROM threats
            ORDER BY seen_at DESC
            LIMIT 50
        `)
		}

		json.NewEncoder(w).Encode(data)
	})
	log.Println("🚀 Dashboard live at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ArcData represents one threat origin point, ready for globe.gl
type ArcData struct {
	StartLat float64 `json:"startLat"`
	StartLng float64 `json:"startLng"`
	EndLat   float64 `json:"endLat"`
	EndLng   float64 `json:"endLng"`
	Country  string  `json:"country"`
	City     string  `json:"city"`
	Count    int     `json:"count"`
}

// Roughly the center of India — our fixed "observer" point on the globe
const DASHBOARD_LAT = 20.5937
const DASHBOARD_LNG = 78.9629
