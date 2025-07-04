package semantic

import (
	"net"
	"regexp"
	"strings"
	"time"

	"security-monitor/internal/models"
)

// Funciones auxiliares para el análisis semántico

func (a *Analyzer) extractOriginalCommand(ast *models.ASTNode) string {
	return a.reconstructCommand(ast)
}

func (a *Analyzer) reconstructCommand(node *models.ASTNode) string {
	var parts []string
	
	switch node.Type {
	case "CommandName", "Argument", "Flag", "RedirectionTarget":
		if node.Value != "" {
			parts = append(parts, node.Value)
		}
	case "Pipe":
		parts = append(parts, "|")
	case "Separator":
		parts = append(parts, node.Value)
	case "LogicalOperator":
		parts = append(parts, node.Value)
	case "Redirection":
		parts = append(parts, node.Value)
	}
	
	for _, child := range node.Children {
		childParts := a.reconstructCommand(child)
		if childParts != "" {
			parts = append(parts, childParts)
		}
	}
	
	return strings.Join(parts, " ")
}

func (a *Analyzer) getCommandName(node *models.ASTNode) string {
	for _, child := range node.Children {
		if child.Type == "CommandName" {
			return child.Value
		}
	}
	return ""
}

func (a *Analyzer) hasExternalIPs(node *models.ASTNode) bool {
	ips := a.extractIPAddresses(node)
	for _, ip := range ips {
		if a.isExternalIP(ip) {
			return true
		}
	}
	return false
}

func (a *Analyzer) hasPermissivePermissions(node *models.ASTNode) bool {
	for _, child := range node.Children {
		if child.Type == "Argument" && (child.Value == "777" || child.Value == "666") {
			return true
		}
	}
	return false
}

func (a *Analyzer) extractPipelineCommands(node *models.ASTNode) []string {
	var commands []string
	
	for _, child := range node.Children {
		if child.Type == "Command" {
			cmdName := a.getCommandName(child)
			if cmdName != "" {
				commands = append(commands, cmdName)
			}
		}
	}
	
	return commands
}

func (a *Analyzer) extractFilePaths(node *models.ASTNode) []string {
	var paths []string
	
	if node.Type == "Argument" && node.Token != nil && node.Token.Type == models.PATH {
		paths = append(paths, node.Value)
	}
	
	for _, child := range node.Children {
		paths = append(paths, a.extractFilePaths(child)...)
	}
	
	return paths
}

func (a *Analyzer) extractIPAddresses(node *models.ASTNode) []string {
	var ips []string
	
	if node.Type == "Argument" && node.Token != nil && node.Token.Type == models.IP_ADDRESS {
		ips = append(ips, node.Value)
	}
	
	for _, child := range node.Children {
		ips = append(ips, a.extractIPAddresses(child)...)
	}
	
	return ips
}

func (a *Analyzer) extractURLs(node *models.ASTNode) []string {
	var urls []string
	
	if node.Type == "Argument" && node.Token != nil && node.Token.Type == models.URL {
		urls = append(urls, node.Value)
	}
	
	for _, child := range node.Children {
		urls = append(urls, a.extractURLs(child)...)
	}
	
	return urls
}

func (a *Analyzer) isExternalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Verificar si es IP privada
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return false
		}
	}
	
	return true
}

func (a *Analyzer) isSuspiciousURL(url string) bool {
	suspiciousPatterns := []string{
		`bit\.ly`,
		`tinyurl\.com`,
		`pastebin\.com`,
		`raw\.githubusercontent\.com`,
		`ngrok\.io`,
		`duckdns\.org`,
		`\.tk$`,
		`\.ml$`,
		`\.ga$`,
		`\.cf$`,
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, url); matched {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) isSensitiveFilePattern(path string) bool {
	sensitivePatterns := []string{
		`/etc/passwd`,
		`/etc/shadow`,
		`/etc/hosts`,
		`/etc/sudoers`,
		`/root/`,
		`\.ssh/`,
		`\.bash_history`,
		`\.mysql_history`,
		`/var/log/`,
		`/proc/`,
		`/sys/`,
		`\.key$`,
		`\.pem$`,
		`\.p12$`,
		`\.pfx$`,
		`config`,
		`credentials`,
		`password`,
	}
	
	lowerPath := strings.ToLower(path)
	for _, pattern := range sensitivePatterns {
		if matched, _ := regexp.MatchString(pattern, lowerPath); matched {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) isReconCommand(command string) bool {
	reconCommands := map[string]bool{
		"whoami": true, "id": true, "uname": true, "hostname": true,
		"ps": true, "netstat": true, "ss": true, "lsof": true,
		"find": true, "locate": true, "which": true, "whereis": true,
		"env": true, "printenv": true, "set": true,
	}
	
	return reconCommands[command]
}

func (a *Analyzer) matchesPattern(ast *models.ASTNode, pattern models.SuspiciousPattern) bool {
	command := a.extractOriginalCommand(ast)
	
	// Verificar coincidencia por regex
	if pattern.Regex != "" {
		if matched, _ := regexp.MatchString(pattern.Regex, command); matched {
			return true
		}
	}
	
	// Verificar coincidencia por comandos específicos
	for _, cmd := range pattern.Commands {
		if strings.Contains(command, cmd) {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) updateUserContext(user string, command string, timestamp time.Time) {
	if _, exists := a.userContexts[user]; !exists {
		a.userContexts[user] = &models.UserContext{
			Username:        user,
			LastCommands:    []string{},
			SessionStart:    timestamp,
			FailedAttempts:  0,
			PrivilegeLevel:  "user",
			WorkingDir:      "/home/" + user,
			SuspiciousScore: 0.0,
		}
	}
	
	context := a.userContexts[user]
	
	// Mantener solo los últimos 10 comandos
	context.LastCommands = append(context.LastCommands, command)
	if len(context.LastCommands) > 10 {
		context.LastCommands = context.LastCommands[1:]
	}
}

func (a *Analyzer) initializeRules() {
	a.rules = []models.SecurityRule{
		{
			ID:          "PRIV_ESC_SUDO",
			Name:        "Escalación con sudo",
			Description: "Uso de sudo para ejecutar comandos",
			Pattern:     "^sudo\\s+",
			Category:    models.PrivilegeEscalation,
			Severity:    models.HighRisk,
			Action:      "ALERT",
			Enabled:     true,
		},
		{
			ID:          "DATA_EXFIL_CURL",
			Name:        "Exfiltración con curl",
			Description: "Uso de curl para enviar datos",
			Pattern:     "curl.*-d\\s+@",
			Category:    models.DataExfiltration,
			Severity:    models.CriticalRisk,
			Action:      "BLOCK",
			Enabled:     true,
		},
		{
			ID:          "RECON_ENUM",
			Name:        "Enumeración del sistema",
			Description: "Comandos de reconocimiento del sistema",
			Pattern:     "(whoami|id|uname|hostname)\\s*$",
			Category:    models.Reconnaissance,
			Severity:    models.MediumRisk,
			Action:      "LOG",
			Enabled:     true,
		},
		{
			ID:          "PERSIST_CRON",
			Name:        "Persistencia con cron",
			Description: "Modificación de tareas programadas",
			Pattern:     "crontab\\s+-e",
			Category:    models.Persistence,
			Severity:    models.HighRisk,
			Action:      "ALERT",
			Enabled:     true,
		},
		{
			ID:          "NET_SHELL",
			Name:        "Shell reversa",
			Description: "Intento de shell reversa con netcat",
			Pattern:     "nc.*-l.*-p\\s+\\d+",
			Category:    models.NetworkActivity,
			Severity:    models.CriticalRisk,
			Action:      "BLOCK",
			Enabled:     true,
		},
	}
}

func (a *Analyzer) initializeSuspiciousFiles() {
	a.suspiciousFiles = map[string]float64{
		"/etc/passwd":       8.0,
		"/etc/shadow":       9.0,
		"/etc/sudoers":      8.5,
		"/etc/hosts":        6.0,
		"/root/.bashrc":     7.0,
		"/root/.ssh":        8.0,
		"/var/log/auth.log": 6.5,
		"/var/log/secure":   6.5,
		"/home/*/.ssh":      7.5,
		"/tmp":              3.0,
		"/dev/shm":          4.0,
		"/var/tmp":          3.5,
		"/proc/version":     5.0,
		"/proc/cpuinfo":     4.0,
		"/sys/class/net":    5.5,
	}
}

func (a *Analyzer) initializePatterns() {
	a.patterns = []models.SuspiciousPattern{
		{
			Name:        "Shell Reversa Básica",
			Description: "Intento de establecer shell reversa",
			Commands:    []string{"nc", "ncat", "bash", "/dev/tcp"},
			Regex:       `(nc|ncat).*-l.*-p\s+\d+|bash\s+.*>/dev/tcp/`,
			RiskScore:   9.0,
			Category:    models.NetworkActivity,
		},
		{
			Name:        "Exfiltración con Base64",
			Description: "Codificación y exfiltración de datos",
			Commands:    []string{"base64", "curl", "wget"},
			Regex:       `base64.*\|.*(curl|wget)`,
			RiskScore:   8.5,
			Category:    models.DataExfiltration,
		},
		{
			Name:        "Descarga de Payloads",
			Description: "Descarga de archivos ejecutables",
			Commands:    []string{"wget", "curl"},
			Regex:       `(wget|curl).*\.(sh|py|pl|elf|bin)`,
			RiskScore:   7.5,
			Category:    models.DefenseEvasion,
		},
		{
			Name:        "Modificación de Permisos Críticos",
			Description: "Cambio de permisos a archivos del sistema",
			Commands:    []string{"chmod"},
			Regex:       `chmod\s+(777|755|644).*/(etc|usr|var|sys|proc)`,
			RiskScore:   8.0,
			Category:    models.SystemModification,
		},
		{
			Name:        "Búsqueda de Archivos SUID",
			Description: "Búsqueda de binarios con permisos SUID",
			Commands:    []string{"find"},
			Regex:       `find.*-perm.*[us]\+s`,
			RiskScore:   6.5,
			Category:    models.PrivilegeEscalation,
		},
		{
			Name:        "Limpieza de Logs",
			Description: "Intento de borrar logs del sistema",
			Commands:    []string{"rm", "shred", ">"},
			Regex:       `(rm|shred).*/(var/log|\.bash_history)|>\s*/var/log`,
			RiskScore:   7.0,
			Category:    models.DefenseEvasion,
		},
		{
			Name:        "Enumeración de Red",
			Description: "Escaneo de red y puertos",
			Commands:    []string{"nmap", "nc", "ping"},
			Regex:       `nmap.*-s[STAU]|nc.*-z.*-v|ping.*-c\s+\d+.*192\.168|10\.|172\.`,
			RiskScore:   5.5,
			Category:    models.Reconnaissance,
		},
		{
			Name:        "Persistencia por SSH",
			Description: "Modificación de claves SSH autorizadas",
			Commands:    []string{"echo", "cat", ">>"},
			Regex:       `(echo|cat).*>>.*authorized_keys`,
			RiskScore:   8.5,
			Category:    models.Persistence,
		},
		{
			Name:        "Dumping de Memoria",
			Description: "Volcado de memoria de procesos",
			Commands:    []string{"dd", "hexdump", "strings"},
			Regex:       `dd.*if=/dev/mem|strings\s+/proc/\d+/mem`,
			RiskScore:   7.5,
			Category:    models.DataExfiltration,
		},
		{
			Name:        "Túnel SSH",
			Description: "Establecimiento de túnel SSH",
			Commands:    []string{"ssh"},
			Regex:       `ssh.*-[LRD]\s+\d+:`,
			RiskScore:   6.0,
			Category:    models.LateralMovement,
		},
	}
}