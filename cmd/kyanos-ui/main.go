package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed web/*
var webFS embed.FS

func main() {
	var redisAddr, redisPass, redisKey, listen string
	var redisDB int
	flag.StringVar(&redisAddr, "redis-addr", "127.0.0.1:6379", "redis address")
	flag.StringVar(&redisPass, "redis-password", "", "redis password")
	flag.IntVar(&redisDB, "redis-db", 0, "redis db")
	flag.StringVar(&redisKey, "redis-key", "kyanos:flows", "redis list key")
	flag.StringVar(&listen, "listen", ":18080", "listen address")
	flag.Parse()

	client := redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPass, DB: redisDB})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) {
		// The UI reads the same compact FlowRecord JSON that the CLI stores in
		// Redis, so the browser view and JSON lines stay in sync.
		limit := int64(100)
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		items, err := client.LRange(r.Context(), redisKey, 0, limit-1).Result()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		flows := make([]map[string]any, 0, len(items))
		for _, item := range items {
			var obj map[string]any
			if err := json.Unmarshal([]byte(item), &obj); err != nil {
				continue
			}
			if search != "" {
				bs, _ := json.Marshal(obj)
				if !strings.Contains(strings.ToLower(string(bs)), search) {
					continue
				}
			}
			flows = append(flows, obj)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": flows})
	})
	mux.HandleFunc("/api/flow/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/flow/")
		items, err := client.LRange(r.Context(), redisKey, 0, 999).Result()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, item := range items {
			var obj map[string]any
			if err := json.Unmarshal([]byte(item), &obj); err != nil {
				continue
			}
			if obj["id"] == id {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(item))
				return
			}
		}
		http.NotFound(w, r)
	})
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	log.Printf("kyanos-ui listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}
