package semantic

import (
	"fmt"
	"time"

	"security-monitor/internal/models"
)

type Analyzer struct {
	rules           []models.SecurityRule
	suspiciousFiles map[string]float64
	userContexts    map[string]*models.UserContext
	patterns        []models.SuspiciousPattern
}

func New() *Analyzer {
	analyzer := &Analyzer{
		suspiciousFiles: make(map[string]float64),
		userContexts:    make(map[string]*models.UserContext),
	}
	
	analyzer.initializeRules()
	analyzer.initializeSuspiciousFiles()
	analyzer.initializePatterns()
	
	return analyzer
}

func (a *Analyzer) Analyze(ast *models.ASTNode, user string, timestamp time.Time) (*models.AnalysisResult, error) {
	startTime := time.Now()
	
	result := &models.AnalysisResult{
		OriginalCommand:  a.extractOriginalCommand(ast),
		User:            user,
		Timestamp:       timestamp,
		AST:             ast,
		RiskScore:       0.0,
		RiskLevel:       models.NoRisk,
		ThreatCategories: []models.ThreatCategory{},
		Reasons:         []string{},
		Recommendations: []string{},
		IsBlocked:       false,
	}

	// Actualizar contexto del usuario
	a.updateUserContext(user, result.OriginalCommand, timestamp)

	// Análisis de comportamiento
	a.analyzeBehavior(ast, result)
	
	// Análisis de patrones sospechosos
	a.analyzePatterns(ast, result)
	
	// Análisis temporal
	a.analyzeTemporalPatterns(user, timestamp, result)
	
	// Análisis de archivos sensibles
	a.analyzeSensitiveFiles(ast, result)
	
	// Análisis de red
	a.analyzeNetworkActivity(ast, result)
	
	// Cálculo final de riesgo
	a.calculateFinalRisk(result)
	
	result.ProcessingTime = time.Since(startTime)
	
	return result, nil
}

func (a *Analyzer) analyzeBehavior(ast *models.ASTNode, result *models.AnalysisResult) {
	behaviors := a.extractBehaviors(ast)
	
	for _, behavior := range behaviors {
		switch behavior.Type {
		case "privilege_escalation":
			result.RiskScore += 8.0
			result.ThreatCategories = append(result.ThreatCategories, models.PrivilegeEscalation)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "data_exfiltration":
			result.RiskScore += 7.5
			result.ThreatCategories = append(result.ThreatCategories, models.DataExfiltration)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "reconnaissance":
			result.RiskScore += 5.0
			result.ThreatCategories = append(result.ThreatCategories, models.Reconnaissance)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "persistence":
			result.RiskScore += 6.5
			result.ThreatCategories = append(result.ThreatCategories, models.Persistence)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "lateral_movement":
			result.RiskScore += 6.0
			result.ThreatCategories = append(result.ThreatCategories, models.LateralMovement)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "defense_evasion":
			result.RiskScore += 5.5
			result.ThreatCategories = append(result.ThreatCategories, models.DefenseEvasion)
			result.Reasons = append(result.Reasons, behavior.Description)
			
		case "network_activity":
			result.RiskScore += 4.0
			result.ThreatCategories = append(result.ThreatCategories, models.NetworkActivity)
			result.Reasons = append(result.Reasons, behavior.Description)
		}
	}
}

type Behavior struct {
	Type        string
	Description string
	Severity    float64
}

func (a *Analyzer) extractBehaviors(node *models.ASTNode) []Behavior {
	var behaviors []Behavior
	
	switch node.Type {
	case "Command":
		command := a.getCommandName(node)
		behaviors = append(behaviors, a.analyzeCommand(command, node)...)
		
	case "Pipeline":
		behaviors = append(behaviors, a.analyzePipeline(node)...)
	}
	
	for _, child := range node.Children {
		behaviors = append(behaviors, a.extractBehaviors(child)...)
	}
	
	return behaviors
}

func (a *Analyzer) analyzeCommand(command string, node *models.ASTNode) []Behavior {
	var behaviors []Behavior
	
	// Comandos de escalación de privilegios
	privEscalationCommands := map[string]string{
		"sudo":   "Ejecución con privilegios elevados",
		"su":     "Cambio de usuario",
		"passwd": "Modificación de contraseña",
	}
	
	if desc, exists := privEscalationCommands[command]; exists {
		behaviors = append(behaviors, Behavior{
			Type:        "privilege_escalation",
			Description: desc,
			Severity:    8.0,
		})
	}
	
	// Comandos de reconocimiento
	reconCommands := map[string]string{
		"whoami":   "Identificación de usuario actual",
		"id":       "Consulta de identificadores de usuario",
		"uname":    "Información del sistema",
		"hostname": "Consulta de nombre del host",
		"ps":       "Listado de procesos",
		"netstat":  "Consulta de conexiones de red",
		"ss":       "Análisis de sockets",
		"lsof":     "Archivos abiertos por procesos",
		"find":     "Búsqueda en sistema de archivos",
	}
	
	if desc, exists := reconCommands[command]; exists {
		behaviors = append(behaviors, Behavior{
			Type:        "reconnaissance",
			Description: desc,
			Severity:    5.0,
		})
	}
	
	// Comandos de persistencia
	persistenceCommands := map[string]string{
		"crontab":    "Programación de tareas",
		"systemctl":  "Gestión de servicios del sistema",
		"service":    "Control de servicios",
		"chkconfig":  "Configuración de servicios de arranque",
	}
	
	if desc, exists := persistenceCommands[command]; exists {
		behaviors = append(behaviors, Behavior{
			Type:        "persistence",
			Description: desc,
			Severity:    6.5,
		})
	}
	
	// Comandos de red
	networkCommands := map[string]string{
		"curl":   "Transferencia de datos HTTP",
		"wget":   "Descarga de archivos web",
		"nc":     "Netcat - conexión de red",
		"ncat":   "Ncat - conexión de red mejorada",
		"ssh":    "Conexión SSH",
		"scp":    "Copia segura por red",
		"rsync":  "Sincronización remota",
		"telnet": "Conexión Telnet",
	}
	
	if desc, exists := networkCommands[command]; exists {
		behaviors = append(behaviors, Behavior{
			Type:        "network_activity",
			Description: desc,
			Severity:    4.0,
		})
		
		// Verificar si hay IPs externas
		if a.hasExternalIPs(node) {
			behaviors = append(behaviors, Behavior{
				Type:        "data_exfiltration",
				Description: "Comunicación con direcciones IP externas",
				Severity:    7.5,
			})
		}
	}
	
	// Análisis específico de chmod
	if command == "chmod" {
		if a.hasPermissivePermissions(node) {
			behaviors = append(behaviors, Behavior{
				Type:        "privilege_escalation",
				Description: "Asignación de permisos permisivos (777)",
				Severity:    6.0,
			})
		}
	}
	
	return behaviors
}

func (a *Analyzer) analyzePipeline(node *models.ASTNode) []Behavior {
	var behaviors []Behavior
	
	commands := a.extractPipelineCommands(node)
	
	// Detectar patrones de exfiltración en pipelines
	if len(commands) >= 2 {
		firstCmd := commands[0]
		lastCmd := commands[len(commands)-1]
		
		// Patrón: cat archivo | curl/wget
		if (firstCmd == "cat" || firstCmd == "grep") && 
		   (lastCmd == "curl" || lastCmd == "wget") {
			behaviors = append(behaviors, Behavior{
				Type:        "data_exfiltration",
				Description: "Pipeline de exfiltración de datos",
				Severity:    8.5,
			})
		}
		
		// Patrón: comando | nc (envío por netcat)
		if lastCmd == "nc" || lastCmd == "ncat" {
			behaviors = append(behaviors, Behavior{
				Type:        "data_exfiltration",
				Description: "Envío de datos por netcat",
				Severity:    7.0,
			})
		}
	}
	
	return behaviors
}

func (a *Analyzer) analyzePatterns(ast *models.ASTNode, result *models.AnalysisResult) {
	for _, pattern := range a.patterns {
		if a.matchesPattern(ast, pattern) {
			result.RiskScore += pattern.RiskScore
			result.ThreatCategories = append(result.ThreatCategories, pattern.Category)
			result.Reasons = append(result.Reasons, pattern.Description)
		}
	}
}

func (a *Analyzer) analyzeTemporalPatterns(user string, timestamp time.Time, result *models.AnalysisResult) {
	hour := timestamp.Hour()
	
	// Horarios sospechosos (fuera del horario laboral)
	if hour < 6 || hour > 22 {
		result.RiskScore += 2.0
		result.Reasons = append(result.Reasons, "Actividad fuera del horario laboral")
	}
	
	// Análisis de contexto del usuario
	if context, exists := a.userContexts[user]; exists {
		// Múltiples comandos de reconocimiento en poco tiempo
		reconCount := 0
		for _, cmd := range context.LastCommands {
			if a.isReconCommand(cmd) {
				reconCount++
			}
		}
		
		if reconCount >= 3 {
			result.RiskScore += 3.0
			result.Reasons = append(result.Reasons, "Múltiples comandos de reconocimiento")
		}
	}
}

func (a *Analyzer) analyzeSensitiveFiles(ast *models.ASTNode, result *models.AnalysisResult) {
	paths := a.extractFilePaths(ast)
	
	for _, path := range paths {
		if score, exists := a.suspiciousFiles[path]; exists {
			result.RiskScore += score
			result.Reasons = append(result.Reasons, 
				fmt.Sprintf("Acceso a archivo sensible: %s", path))
		}
		
		// Verificar patrones de archivos sensibles
		if a.isSensitiveFilePattern(path) {
			result.RiskScore += 4.0
			result.Reasons = append(result.Reasons, 
				fmt.Sprintf("Patrón de archivo sensible: %s", path))
		}
	}
}

func (a *Analyzer) analyzeNetworkActivity(ast *models.ASTNode, result *models.AnalysisResult) {
	ips := a.extractIPAddresses(ast)
	urls := a.extractURLs(ast)
	
	for _, ip := range ips {
		if a.isExternalIP(ip) {
			result.RiskScore += 3.0
			result.ThreatCategories = append(result.ThreatCategories, models.NetworkActivity)
			result.Reasons = append(result.Reasons, 
				fmt.Sprintf("Comunicación con IP externa: %s", ip))
		}
	}
	
	for _, url := range urls {
		if a.isSuspiciousURL(url) {
			result.RiskScore += 5.0
			result.ThreatCategories = append(result.ThreatCategories, models.DataExfiltration)
			result.Reasons = append(result.Reasons, 
				fmt.Sprintf("URL sospechosa: %s", url))
		}
	}
}

func (a *Analyzer) calculateFinalRisk(result *models.AnalysisResult) {
	// Aplicar factores de multiplicación por categorías críticas
	criticalCategories := map[models.ThreatCategory]float64{
		models.PrivilegeEscalation: 1.5,
		models.DataExfiltration:    1.3,
		models.Persistence:         1.2,
	}
	
	for _, category := range result.ThreatCategories {
		if multiplier, exists := criticalCategories[category]; exists {
			result.RiskScore *= multiplier
		}
	}
	
	// Limitar el score máximo
	if result.RiskScore > 10.0 {
		result.RiskScore = 10.0
	}
	
	// Asignar nivel de riesgo
	switch {
	case result.RiskScore >= models.CriticalRiskScore:
		result.RiskLevel = models.CriticalRisk
		result.IsBlocked = true
	case result.RiskScore >= models.HighRiskScore:
		result.RiskLevel = models.HighRisk
	case result.RiskScore >= models.MediumRiskScore:
		result.RiskLevel = models.MediumRisk
	case result.RiskScore >= models.LowRiskScore:
		result.RiskLevel = models.LowRisk
	default:
		result.RiskLevel = models.NoRisk
	}
	
	// Generar recomendaciones
	a.generateRecommendations(result)
}

func (a *Analyzer) generateRecommendations(result *models.AnalysisResult) {
	for _, category := range result.ThreatCategories {
		switch category {
		case models.PrivilegeEscalation:
			result.Recommendations = append(result.Recommendations, 
				"Revisar políticas de sudo y acceso administrativo")
		case models.DataExfiltration:
			result.Recommendations = append(result.Recommendations, 
				"Implementar DLP y monitoreo de tráfico de red")
		case models.Reconnaissance:
			result.Recommendations = append(result.Recommendations, 
				"Monitorear actividad de reconocimiento del usuario")
		case models.Persistence:
			result.Recommendations = append(result.Recommendations, 
				"Auditar cambios en servicios y tareas programadas")
		}
	}
	
	if result.RiskScore >= models.HighRiskScore {
		result.Recommendations = append(result.Recommendations, 
			"Investigar inmediatamente la actividad del usuario")
	}
}