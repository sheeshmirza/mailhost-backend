package api

import (
	"net/http"
	"time"
)

type counts struct {
	Sent      int64 `json:"sent"`
	Delivered int64 `json:"delivered"`
	Bounced   int64 `json:"bounced"`
	Failed    int64 `json:"failed"`
	Opened    int64 `json:"opened"`
	Clicked   int64 `json:"clicked"`
}

func (c *counts) add(typ string, n int64) {
	switch typ {
	case "sent":
		c.Sent += n
	case "delivered":
		c.Delivered += n
	case "bounced":
		c.Bounced += n
	case "failed":
		c.Failed += n
	case "opened":
		c.Opened += n
	case "clicked":
		c.Clicked += n
	}
}

type bucket struct {
	Bucket time.Time `json:"bucket"`
	counts
}

var intervals = map[string]time.Duration{"hour": 31 * 24 * time.Hour, "day": 366 * 24 * time.Hour, "week": 366 * 24 * time.Hour, "month": 366 * 24 * time.Hour}

// analytics: GET /v1/analytics?from=&to=&interval=hour|day|week|month&domain_id=
func (s *Server) analytics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)
	var err error
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "from must be an RFC 3339 timestamp")
			return
		}
	}
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "to must be an RFC 3339 timestamp")
			return
		}
	}
	interval := q.Get("interval")
	if interval == "" {
		interval = "day"
	}
	maxRange, ok := intervals[interval]
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, "interval must be hour, day, week or month")
		return
	}
	if !from.Before(to) {
		writeError(w, http.StatusUnprocessableEntity, "invalid range: from must be before to")
		return
	}
	if to.Sub(from) > maxRange {
		writeError(w, http.StatusUnprocessableEntity, "analytics range is too large for interval "+interval)
		return
	}
	domainID, ok := optionalUUID(w, r, "domain_id")
	if !ok {
		return
	}

	// Hourly rollups make long-running analytics queries proportional to the
	// number of hours, not the number of delivery events. The two partial-hour
	// edges still read raw events so arbitrary from/to values remain exact.
	rollFrom := from.UTC().Truncate(time.Hour)
	if rollFrom.Before(from.UTC()) {
		rollFrom = rollFrom.Add(time.Hour)
	}
	rollTo := to.UTC().Truncate(time.Hour)
	leftEnd, rightStart := to, to
	if rollFrom.Before(rollTo) {
		leftEnd, rightStart = rollFrom, rollTo
	} else {
		rollFrom, rollTo = to, to
	}

	rows, err := s.rdb.Query(r.Context(), `
WITH counts AS (
    SELECT date_trunc($4::text, bucket AT TIME ZONE 'UTC') AS bucket, type, sum(count)::bigint AS count
    FROM event_rollups
    WHERE account_id = $1 AND bucket >= $2 AND bucket < $3
      AND ($5::uuid IS NULL OR domain_id = $5::uuid)
	AND type IN ('sent', 'delivered', 'bounced', 'failed', 'opened', 'clicked')
    GROUP BY 1, 2
    UNION ALL
    SELECT date_trunc($4::text, created_at AT TIME ZONE 'UTC') AS bucket, type, count(*)::bigint AS count
    FROM events
    WHERE account_id = $1 AND created_at >= $6 AND created_at < $7
      AND ($5::uuid IS NULL OR domain_id = $5::uuid)
	AND type IN ('sent', 'delivered', 'bounced', 'failed', 'opened', 'clicked')
    GROUP BY 1, 2
    UNION ALL
    SELECT date_trunc($4::text, created_at AT TIME ZONE 'UTC') AS bucket, type, count(*)::bigint AS count
    FROM events
    WHERE account_id = $1 AND created_at >= $8 AND created_at < $9
      AND ($5::uuid IS NULL OR domain_id = $5::uuid)
	AND type IN ('sent', 'delivered', 'bounced', 'failed', 'opened', 'clicked')
    GROUP BY 1, 2
)
SELECT bucket, type, sum(count)::bigint AS count
FROM counts
GROUP BY 1, 2 ORDER BY 1`, accountID(r), rollFrom, rollTo, interval, domainID, from, leftEnd, rightStart, to)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	var totals counts
	series := []*bucket{}
	for rows.Next() {
		var t time.Time
		var typ string
		var n int64
		if err := rows.Scan(&t, &typ, &n); err != nil {
			s.internal(w, err)
			return
		}
		if len(series) == 0 || !series[len(series)-1].Bucket.Equal(t) {
			series = append(series, &bucket{Bucket: t})
		}
		series[len(series)-1].add(typ, n)
		totals.add(typ, n)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}

	rate := func(n int64) float64 {
		if totals.Sent == 0 {
			return 0
		}
		return float64(n) / float64(totals.Sent)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "interval": interval, "domain_id": domainID,
		"totals": totals,
		"rates": map[string]float64{
			"delivery_rate": rate(totals.Delivered),
			"bounce_rate":   rate(totals.Bounced),
			"failure_rate":  rate(totals.Failed),
			"open_rate":     rate(totals.Opened),
			"click_rate":    rate(totals.Clicked),
		},
		"series": series,
	})
}
