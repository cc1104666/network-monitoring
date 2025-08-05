package main

import (
	"encoding/json"
	"net/http"
)

func getStatsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		stats := monitor.GetCurrentStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
	}
}

func getServersHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		servers := monitor.GetServerStatus()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    servers,
		})
	}
}

func getThreatsHandler(detector *ThreatDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		threats := detector.GetAllThreats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    threats,
		})
	}
}

func getEndpointsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		endpoints := monitor.GetEndpointStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    endpoints,
		})
	}
}

func getRequestDetailsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		endpoint := r.URL.Query().Get("endpoint")
		var details []RequestDetail
		
		if endpoint != "" {
			details = monitor.GetRequestDetailsByEndpoint(endpoint)
		} else {
			details = monitor.GetRequestDetails()
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    details,
		})
	}
}
