package a

import (
	"log/slog"
)

func TestLogs() {
	// Правильные логи:
	slog.Info("starting server")
	slog.Info("server started on port 8080")

	// Нарушения:
	slog.Info("Starting server") // want "must start with a lowercase letter"

	slog.Info("запуск сервера") // want "must contain only English letters"

	slog.Info("server started!") // want "must contain only English letters"

	password := "123"
	slog.Info("user password: " + password) // want "contains sensitive data"
}
