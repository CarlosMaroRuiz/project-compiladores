package models

import (
	"fmt"
	"time"
)

// TokenType define los tipos de tokens reconocidos
type TokenType int

const (
	// Tokens básicos
	COMMAND TokenType = iota
	PARAMETER
	FLAG
	PATH
	OPERATOR
	REDIRECT
	PIPE
	SEMICOLON
	AMPERSAND
	IP_ADDRESS
	PORT
	URL
	VARIABLE
	SPECIAL_CHAR
	STRING
	NUMBER
	ENCODED
	WILDCARD
	EOF
)

var tokenNames = map[TokenType]string{
	COMMAND:      "COMMAND",
	PARAMETER:    "PARAMETER",
	FLAG:         "FLAG",
	PATH:         "PATH",
	OPERATOR:     "OPERATOR",
	REDIRECT:     "REDIRECT",
	PIPE:         "PIPE",
	SEMICOLON:    "SEMICOLON",
	AMPERSAND:    "AMPERSAND",
	IP_ADDRESS:   "IP_ADDRESS",
	PORT:         "PORT",
	URL:          "URL",
	VARIABLE:     "VARIABLE",
	SPECIAL_CHAR: "SPECIAL_CHAR",
	STRING:       "STRING",
	NUMBER:       "NUMBER",
	ENCODED:      "ENCODED",
	WILDCARD:     "WILDCARD",
	EOF:          "EOF",
}

func (t TokenType) String() string {
	if name, ok := tokenNames[t]; ok {
		return name
	}
	return "UNKNOWN"
}

// Token representa un token individual
type Token struct {
	Type     TokenType
	Value    string
	Position int
	Line     int
	Column   int
}

// CommandInput representa un comando de entrada
type CommandInput struct {
	Command   string
	User      string
	Timestamp time.Time
	Source    string // terminal, script, etc.
}

// ASTNode representa un nodo en el árbol de sintaxis abstracta
type ASTNode struct {
	Type     string
	Value    string
	Children []*ASTNode
	Token    *Token
}

// RiskLevel define los niveles de riesgo
type RiskLevel string

const (
	NoRisk       RiskLevel = "SIN_RIESGO"
	LowRisk      RiskLevel = "BAJO"
	MediumRisk   RiskLevel = "MEDIO"
	HighRisk     RiskLevel = "ALTO"
	CriticalRisk RiskLevel = "CRÍTICO"
)

// Puntuaciones numéricas para los niveles de riesgo
const (
	NoRiskScore       float64 = 0.0
	LowRiskScore      float64 = 2.5
	MediumRiskScore   float64 = 5.0
	HighRiskScore     float64 = 7.5
	CriticalRiskScore float64 = 10.0
)

// ThreatCategory define categorías de amenazas
type ThreatCategory string

const (
	PrivilegeEscalation ThreatCategory = "ESCALACIÓN_PRIVILEGIOS"
	DataExfiltration    ThreatCategory = "EXFILTRACIÓN_DATOS"
	Reconnaissance      ThreatCategory = "RECONOCIMIENTO"
	Persistence         ThreatCategory = "PERSISTENCIA"
	LateralMovement     ThreatCategory = "MOVIMIENTO_LATERAL"
	DefenseEvasion      ThreatCategory = "EVASIÓN_DEFENSAS"
	NetworkActivity     ThreatCategory = "ACTIVIDAD_RED"
	SystemModification ThreatCategory = "MODIFICACIÓN_SISTEMA"
)

// AnalysisResult contiene el resultado del análisis completo
type AnalysisResult struct {
	OriginalCommand   string
	User              string
	Timestamp         time.Time
	Tokens           []Token
	AST              *ASTNode
	RiskScore        float64
	RiskLevel        RiskLevel
	ThreatCategories []ThreatCategory
	Reasons          []string
	Recommendations  []string
	IsBlocked        bool
	ProcessingTime   time.Duration
}

// SuspiciousPattern define patrones sospechosos
type SuspiciousPattern struct {
	Name        string
	Description string
	Commands    []string
	Regex       string
	RiskScore   float64
	Category    ThreatCategory
}

// UserContext mantiene el contexto del usuario
type UserContext struct {
	Username        string
	LastCommands    []string
	SessionStart    time.Time
	FailedAttempts  int
	PrivilegeLevel  string
	WorkingDir      string
	SuspiciousScore float64
}

// Alert representa una alerta generada
type Alert struct {
	ID              string
	Timestamp       time.Time
	User            string
	Command         string
	RiskLevel       RiskLevel
	RiskScore       float64
	Category        ThreatCategory
	Description     string
	Recommendations []string
	Acknowledged    bool
	AcknowledgedBy  string
	AcknowledgedAt  time.Time
}

// CommandCategory clasifica tipos de comandos
type CommandCategory string

const (
	SystemInfo     CommandCategory = "INFORMACIÓN_SISTEMA"
	FileSystem     CommandCategory = "SISTEMA_ARCHIVOS"
	Network        CommandCategory = "RED"
	Process        CommandCategory = "PROCESOS"
	UserManagement CommandCategory = "GESTIÓN_USUARIOS"
	Archive        CommandCategory = "ARCHIVOS_COMPRIMIDOS"
	Text           CommandCategory = "PROCESAMIENTO_TEXTO"
	Monitoring     CommandCategory = "MONITOREO"
	Security       CommandCategory = "SEGURIDAD"
	Unknown        CommandCategory = "DESCONOCIDO"
)

// SecurityRule define una regla de seguridad
type SecurityRule struct {
	ID          string
	Name        string
	Description string
	Pattern     string
	Category    ThreatCategory
	Severity    RiskLevel
	Action      string // LOG, ALERT, BLOCK
	Enabled     bool
}

// ParseError representa errores de parsing
type ParseError struct {
	Message  string
	Token    *Token
	Expected string
	Got      string
}

func (e *ParseError) Error() string {
	if e.Token != nil {
		return fmt.Sprintf("error de parsing en línea %d, columna %d: %s. Esperaba %s, obtuvo %s",
			e.Token.Line, e.Token.Column, e.Message, e.Expected, e.Got)
	}
	return fmt.Sprintf("error de parsing: %s", e.Message)
}

// CommandStats mantiene estadísticas de comandos
type CommandStats struct {
	TotalCommands    int
	RiskyCommands    int
	BlockedCommands  int
	UserStats        map[string]*UserStats
	CategoryStats    map[CommandCategory]int
	ThreatStats      map[ThreatCategory]int
	HourlyActivity   [24]int
	LastUpdated      time.Time
}

// UserStats estadísticas por usuario
type UserStats struct {
	CommandCount    int
	RiskScore       float64
	LastActivity    time.Time
	MostUsedCommand string
	Violations      int
}