package logging

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"time"
)

// newLogger initializes the logger.
func NewLogger() *slog.Logger {
	level := parseLevel(os.Getenv("LOG_LEVEL"))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

type Timed struct {
	start time.Time
}

func StartTimed() Timed {
	return Timed{start: time.Now()}
}

func (t Timed) Elapsed() time.Duration {
	return time.Since(t.start)
}

func (t Timed) Elapsed_ms() int64 {
	return time.Since(t.start).Milliseconds()
}

func NewCorrelationID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		// Fallback: treat unknown as info
		return slog.LevelInfo
	}
}
