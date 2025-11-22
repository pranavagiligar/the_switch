package config

import (
	"flag"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBPath    string
	AdminPass string
	Port      string
	JWTKey    []byte
}

func Load() *Config {
	// Load .env file if present
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️  No .env file found, using defaults or flags")
	}

	// Read from environment (with fallback defaults)
	defaultDBPath := getEnv("DB_PATH", "job_scheduler.db")
	defaultAdminPass := getEnv("ADMIN_PASS", "password")
	jwtKey := []byte(getEnv("JWT_TOKEN_SECRET", ""))
	port := getEnv("PORT", "8080")

	// Define flags (optional override via CLI)
	dbPathPtr := flag.String("db-path", defaultDBPath, "Path to the SQLite database file for persistent storage.")
	adminPassPtr := flag.String("admin-pass", defaultAdminPass, "Set a custom admin password on startup.")
	flag.Parse()

	return &Config{
		DBPath:    *dbPathPtr,
		AdminPass: *adminPassPtr,
		Port:      port,
		JWTKey:    jwtKey,
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
