package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"security-monitor/internal/lexer"
	"security-monitor/internal/models"
	"security-monitor/internal/parser"
	"security-monitor/internal/semantic"
)

type SecurityMonitor struct {
	lexer    *lexer.Lexer
	parser   *parser.Parser
	semantic *semantic.Analyzer
	alerts   []models.AnalysisResult
}

type WebResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type DashboardData struct {
	TotalCommands    int                     `json:"total_commands"`
	HighRiskCommands int                     `json:"high_risk_commands"`
	RecentAlerts     []models.AnalysisResult `json:"recent_alerts"`
	RiskDistribution map[string]int          `json:"risk_distribution"`
	LastUpdate       string                  `json:"last_update"`
}

func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{
		lexer:    lexer.New(),
		parser:   parser.New(),
		semantic: semantic.New(),
		alerts:   make([]models.AnalysisResult, 0),
	}
}

func (sm *SecurityMonitor) ProcessCommand(command string, user string, timestamp time.Time) (*models.AnalysisResult, error) {
	// Fase 1: Análisis Léxico
	tokens, err := sm.lexer.Tokenize(command)
	if err != nil {
		return nil, fmt.Errorf("error en análisis léxico: %w", err)
	}

	// Fase 2: Análisis Sintáctico
	ast, err := sm.parser.Parse(tokens)
	if err != nil {
		return nil, fmt.Errorf("error en análisis sintáctico: %w", err)
	}

	// Fase 3: Análisis Semántico
	result, err := sm.semantic.Analyze(ast, user, timestamp)
	if err != nil {
		return nil, fmt.Errorf("error en análisis semántico: %w", err)
	}

	result.Tokens = tokens

	// Almacenar resultado para el dashboard
	sm.alerts = append(sm.alerts, *result)
	
	// Mantener solo los últimos 100 resultados
	if len(sm.alerts) > 100 {
		sm.alerts = sm.alerts[1:]
	}

	return result, nil
}

func (sm *SecurityMonitor) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Command string `json:"command"`
		User    string `json:"user"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		response := WebResponse{
			Success: false,
			Error:   "Invalid JSON format",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if strings.TrimSpace(request.Command) == "" {
		response := WebResponse{
			Success: false,
			Error:   "Command cannot be empty",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	result, err := sm.ProcessCommand(request.Command, request.User, time.Now())
	if err != nil {
		response := WebResponse{
			Success: false,
			Error:   err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := WebResponse{
		Success: true,
		Data:    result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sm *SecurityMonitor) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	riskDistribution := make(map[string]int)
	highRiskCount := 0
	
	for _, alert := range sm.alerts {
		riskDistribution[string(alert.RiskLevel)]++
		if alert.RiskScore >= models.HighRiskScore {
			highRiskCount++
		}
	}

	// Obtener las últimas 10 alertas
	recentAlerts := sm.alerts
	if len(recentAlerts) > 10 {
		recentAlerts = recentAlerts[len(recentAlerts)-10:]
	}

	dashboardData := DashboardData{
		TotalCommands:    len(sm.alerts),
		HighRiskCommands: highRiskCount,
		RecentAlerts:     recentAlerts,
		RiskDistribution: riskDistribution,
		LastUpdate:       time.Now().Format("15:04:05"),
	}

	// Log para depuración
	fmt.Printf("Dashboard Data: Total=%d, HighRisk=%d, Alerts=%d\n", 
		dashboardData.TotalCommands, 
		dashboardData.HighRiskCommands, 
		len(dashboardData.RecentAlerts))

	response := WebResponse{
		Success: true,
		Data:    dashboardData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	monitor := NewSecurityMonitor()

	// Servir archivos estáticos desde la carpeta web/
	fs := http.FileServer(http.Dir("./web/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	
	// Servir index.html en la ruta raíz
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "./web/index.html")
		} else {
			// Intentar servir el archivo desde web/
			http.ServeFile(w, r, "./web"+r.URL.Path)
		}
	})

	// API endpoints
	http.HandleFunc("/api/analyze", monitor.analyzeHandler)
	http.HandleFunc("/api/dashboard", monitor.dashboardHandler)

	fmt.Println("🔍 Security Monitor Web Server")
	fmt.Println("🌐 Servidor iniciado en: http://localhost:8080")
	fmt.Println("📊 Dashboard disponible en: http://localhost:8080")
	fmt.Println("🛡️ Sistema de monitoreo activo...")
	fmt.Println("📁 Asegúrate de que la carpeta 'web/' exista con los archivos HTML, CSS y JS")

	log.Fatal(http.ListenAndServe(":8080", nil))
}