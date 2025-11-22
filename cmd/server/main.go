package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/pranavagiligar/the_switch/internal/config"
	"github.com/pranavagiligar/the_switch/internal/database"
	"github.com/pranavagiligar/the_switch/internal/handlers"
	"github.com/pranavagiligar/the_switch/internal/middleware"
	"github.com/pranavagiligar/the_switch/internal/scheduler"
	"github.com/pranavagiligar/the_switch/internal/ui"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	fmt.Printf("Version: %s, Commit: %s, Built: %s\n", version, commit, buildTime)

	// 1. Load Configuration
	cfg := config.Load()

	// 2. Initialize Database
	if err := database.InitializeDB(cfg.DBPath, cfg.AdminPass); err != nil {
		log.Fatalf("FATAL: Database initialization failed: %v", err)
	}
	defer database.Close()

	// 3. Start Scheduler
	scheduler.StartScheduler()

	// 4. Setup Routes
	mux := http.NewServeMux()

	// Serve index.html and static files (no auth required)
	mux.HandleFunc("/", handlers.ServeIndexFile)
	mux.Handle("/static/", http.FileServer(http.FS(ui.Content)))
	mux.HandleFunc("/login", handlers.LoginHandler(cfg))
	// Expose build metadata for frontend footer
	mux.HandleFunc("/buildinfo", handlers.BuildInfoHandler(version, commit, buildTime))

	// --- API Routes (Authentication required) ---
	apiMux := http.NewServeMux()

	apiMux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
		// Example URL: /api/jobs/job-123/history
		pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/jobs/"), "/")
		jobIDStr := ""
		subPath := ""

		if len(pathParts) > 0 && pathParts[0] != "" {
			jobIDStr = pathParts[0]
		}
		if len(pathParts) > 1 && pathParts[1] != "" {
			subPath = pathParts[1]
		}

		// --- Custom Routing for Job ID Sub-paths ---
		if jobIDStr != "" {
			switch subPath {
			case "run": // Feature 2: Manual Run
				if r.Method == http.MethodPost {
					handlers.RunJobManuallyHandler(w, r)
					return
				}
			case "history": // Feature 1: Execution History
				if r.Method == http.MethodGet {
					handlers.GetJobHistoryHandler(w, r)
					return
				}
			case "skip": // Existing Skip Execution
				if r.Method == http.MethodPost {
					handlers.SkipJobHandler(w, r)
					return
				}
			case "":
				switch r.Method {
				case http.MethodGet:
					handlers.GetJobHandler(w, r)
					return
				case http.MethodDelete:
					handlers.DeleteJobHandler(w, r)
					return
				case http.MethodPut:
					handlers.UpdateJobHandler(w, r)
					return
				}
			}
		}

		// --- Base /api/jobs/ routing ---
		if jobIDStr == "" {
			switch r.Method {
			case http.MethodGet:
				handlers.GetJobsHandler(w, r)
				return
			case http.MethodPost:
				handlers.CreateJobHandler(w, r)
				return
			}
		}

		// Fallback for paths not matching standard patterns
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Add cron interval endpoint for UI validation
	apiMux.HandleFunc("/api/cron/interval", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers.CronIntervalHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Apply authMiddleware to the API routes
	mux.Handle("/api/", middleware.AuthMiddleware(apiMux.ServeHTTP, cfg))

	// Wrap the main router with the CORS middleware
	handler := middleware.EnableCORS(mux)

	serverAddr := ":" + cfg.Port

	log.Printf("Default user: admin")
	if cfg.AdminPass != "password" {
		log.Printf("Admin password successfully set via -admin-pass flag (hashed).")
	} else {
		log.Printf("Admin password is the default 'password' (hashed). Use -admin-pass flag to change.")
	}
	log.Printf("Starting server on http://localhost%s", serverAddr)
	log.Printf("PERSISTENT DATABASE FILE: %s", cfg.DBPath)

	if err := http.ListenAndServe(serverAddr, handler); err != nil && err != http.ErrServerClosed {
		log.Fatalf("FATAL: Could not listen on %s: %v", serverAddr, err)
	}
}
