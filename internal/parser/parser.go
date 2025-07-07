package parser

import (
	"fmt"
	"strings"

	"security-monitor/internal/lexer"
	"security-monitor/internal/models"
)

type Parser struct {
	tokens   []models.Token
	position int
	current  models.Token
}

func New() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(tokens []models.Token) (*models.ASTNode, error) {
	p.tokens = tokens
	p.position = 0
	if len(tokens) > 0 {
		p.current = tokens[0]
	}

	return p.parseCommandLine()
}

func (p *Parser) parseCommandLine() (*models.ASTNode, error) {
	root := &models.ASTNode{
		Type:     "CommandLine",
		Children: []*models.ASTNode{},
	}

	for p.current.Type != models.EOF {
		pipeline, err := p.parsePipeline()
		if err != nil {
			return nil, err
		}
		
		root.Children = append(root.Children, pipeline)

		// Verificar separadores entre comandos
		if p.current.Type == models.SEMICOLON {
			separator := &models.ASTNode{
				Type:  "Separator",
				Value: p.current.Value,
				Token: &p.current,
			}
			root.Children = append(root.Children, separator)
			p.advance()
		} else if p.current.Type == models.AMPERSAND {
			separator := &models.ASTNode{
				Type:  "Separator",
				Value: p.current.Value,
				Token: &p.current,
			}
			root.Children = append(root.Children, separator)
			p.advance()
		} else if p.current.Type == models.OPERATOR {
			// Manejar operadores lógicos && y ||
			operator := &models.ASTNode{
				Type:  "LogicalOperator",
				Value: p.current.Value,
				Token: &p.current,
			}
			root.Children = append(root.Children, operator)
			p.advance()
		} else if p.current.Type != models.EOF {
			// Si no es EOF, continuar - puede ser parte de un comando complejo
			break
		}
	}

	return root, nil
}

func (p *Parser) parsePipeline() (*models.ASTNode, error) {
	pipeline := &models.ASTNode{
		Type:     "Pipeline",
		Children: []*models.ASTNode{},
	}

	// Parsear el primer comando
	cmd, err := p.parseCommand()
	if err != nil {
		return nil, err
	}
	pipeline.Children = append(pipeline.Children, cmd)

	// Parsear pipes adicionales
	for p.current.Type == models.PIPE {
		pipe := &models.ASTNode{
			Type:  "Pipe",
			Value: p.current.Value,
			Token: &p.current,
		}
		pipeline.Children = append(pipeline.Children, pipe)
		p.advance()

		nextCmd, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		pipeline.Children = append(pipeline.Children, nextCmd)
	}

	return pipeline, nil
}

func (p *Parser) parseCommand() (*models.ASTNode, error) {
	command := &models.ASTNode{
		Type:     "Command",
		Children: []*models.ASTNode{},
	}

	// Verificar operadores lógicos (&&, ||) al principio
	if p.current.Type == models.OPERATOR {
		operator := &models.ASTNode{
			Type:  "LogicalOperator",
			Value: p.current.Value,
			Token: &p.current,
		}
		command.Children = append(command.Children, operator)
		p.advance()
	}

	// Verificar que hay un comando válido
	if p.current.Type == models.EOF || 
	   p.current.Type == models.PIPE || 
	   p.current.Type == models.SEMICOLON || 
	   p.current.Type == models.AMPERSAND {
		return nil, &models.ParseError{
			Message:  "se esperaba un comando",
			Token:    &p.current,
			Expected: "comando válido",
			Got:      p.current.Value,
		}
	}

	// NUEVA VALIDACIÓN: Verificar si es un comando inválido
	if p.current.Type == models.INVALID_COMMAND {
		return nil, p.createCommandValidationError(p.current.Value, &p.current)
	}

	// VALIDACIÓN ADICIONAL para comandos PARAMETER que podrían ser comandos mal escritos
	if p.current.Type == models.PARAMETER {
		if validationError := p.ValidateCommand(p.current.Value); validationError != nil {
			validationError.Token = &p.current
			return nil, validationError
		}
	}

	// Nodo del comando principal - ACEPTAR CUALQUIER TIPO DE TOKEN COMO COMANDO
	cmdNode := &models.ASTNode{
		Type:  "CommandName",
		Value: p.current.Value,
		Token: &p.current,
	}
	command.Children = append(command.Children, cmdNode)
	p.advance()

	// Parsear argumentos, flags y redirecciones
	for p.current.Type != models.EOF && 
		p.current.Type != models.PIPE && 
		p.current.Type != models.SEMICOLON && 
		p.current.Type != models.AMPERSAND &&
		p.current.Type != models.OPERATOR {
		
		switch p.current.Type {
		case models.FLAG:
			flag, err := p.parseFlag()
			if err != nil {
				return nil, err
			}
			command.Children = append(command.Children, flag)
			
		case models.REDIRECT:
			redirect, err := p.parseRedirection()
			if err != nil {
				return nil, err
			}
			command.Children = append(command.Children, redirect)
			
		default:
			// ACEPTAR CUALQUIER COSA COMO ARGUMENTO
			arg := &models.ASTNode{
				Type:  "Argument",
				Value: p.current.Value,
				Token: &p.current,
			}
			command.Children = append(command.Children, arg)
			p.advance()
		}
	}

	return command, nil
}

// NUEVAS FUNCIONES PARA VALIDACIÓN DE COMANDOS

// ValidateCommand verifica si un comando es válido y sugiere alternativas
func (p *Parser) ValidateCommand(commandName string) *models.CommandValidationError {
	lexerInstance := lexer.New()
	
	// Verificar si es un comando conocido
	if lexerInstance.IsKnownCommand(commandName) {
		return nil // Comando válido
	}
	
	// Verificar errores de escritura comunes primero
	commonCorrection := lexerInstance.CheckCommonTypos(commandName)
	if commonCorrection != "" {
		return &models.CommandValidationError{
			OriginalCommand: commandName,
			Suggestions: []models.CommandSuggestion{
				{
					Original:  commandName,
					Suggested: commonCorrection,
					Distance:  1,
				},
			},
			Message: fmt.Sprintf("Comando '%s' no reconocido", commandName),
		}
	}
	
	// Buscar sugerencias usando distancia de Levenshtein
	suggestions := lexerInstance.SuggestSimilarCommands(commandName)
	
	if len(suggestions) > 0 {
		return &models.CommandValidationError{
			OriginalCommand: commandName,
			Suggestions:     suggestions,
			Message:         fmt.Sprintf("Comando '%s' no reconocido", commandName),
		}
	}
	
	// Si no hay sugerencias, verificar si parece un comando
	if p.looksLikeCommand(commandName) {
		return &models.CommandValidationError{
			OriginalCommand: commandName,
			Suggestions:     []models.CommandSuggestion{},
			Message:         fmt.Sprintf("Comando '%s' es inválido y no se encontraron sugerencias", commandName),
		}
	}
	
	return nil // No parece ser un comando, podría ser un parámetro válido
}

// createCommandValidationError crea un error de validación con sugerencias
func (p *Parser) createCommandValidationError(commandName string, token *models.Token) *models.CommandValidationError {
	lexerInstance := lexer.New()
	suggestions := lexerInstance.SuggestSimilarCommands(commandName)
	
	return &models.CommandValidationError{
		OriginalCommand: commandName,
		Suggestions:     suggestions,
		Message:         fmt.Sprintf("Comando '%s' no es válido", commandName),
		Token:           token,
	}
}

// looksLikeCommand determina si una cadena parece ser un comando
func (p *Parser) looksLikeCommand(s string) bool {
	// Un comando probable:
	// - Solo contiene letras (a-z, A-Z)
	// - Tiene entre 2 y 20 caracteres
	// - No contiene números ni símbolos especiales
	
	if len(s) < 2 || len(s) > 20 {
		return false
	}
	
	for _, char := range s {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
			return false
		}
	}
	
	return true
}

// FUNCIONES ORIGINALES (sin cambios)

func (p *Parser) parseFlag() (*models.ASTNode, error) {
	flag := &models.ASTNode{
		Type:     "Flag",
		Value:    p.current.Value,
		Token:    &p.current,
		Children: []*models.ASTNode{},
	}
	
	p.advance()
	
	// Algunos flags pueden tener valores
	if p.current.Type == models.PARAMETER || 
	   p.current.Type == models.STRING || 
	   p.current.Type == models.NUMBER ||
	   p.current.Type == models.PATH {
		
		value := &models.ASTNode{
			Type:  "FlagValue",
			Value: p.current.Value,
			Token: &p.current,
		}
		flag.Children = append(flag.Children, value)
		p.advance()
	}
	
	return flag, nil
}

func (p *Parser) parseRedirection() (*models.ASTNode, error) {
	redirect := &models.ASTNode{
		Type:     "Redirection",
		Value:    p.current.Value,
		Token:    &p.current,
		Children: []*models.ASTNode{},
	}
	
	p.advance()
	
	// Debe haber un destino después de la redirección
	if p.current.Type == models.EOF {
		return nil, &models.ParseError{
			Message:  "redirección incompleta",
			Token:    &p.current,
			Expected: "archivo o dispositivo",
			Got:      "fin de línea",
		}
	}
	
	target := &models.ASTNode{
		Type:  "RedirectionTarget",
		Value: p.current.Value,
		Token: &p.current,
	}
	redirect.Children = append(redirect.Children, target)
	p.advance()
	
	return redirect, nil
}

func (p *Parser) advance() {
	if p.position < len(p.tokens)-1 {
		p.position++
		p.current = p.tokens[p.position]
	}
}

func (p *Parser) peek() models.Token {
	if p.position < len(p.tokens)-1 {
		return p.tokens[p.position+1]
	}
	return models.Token{Type: models.EOF}
}

// ValidateSyntax verifica la validez sintáctica del comando
func (p *Parser) ValidateSyntax(ast *models.ASTNode) []string {
	var errors []string
	
	errors = append(errors, p.validateCommandStructure(ast)...)
	errors = append(errors, p.validateRedirections(ast)...)
	errors = append(errors, p.validatePipes(ast)...)
	errors = append(errors, p.validateOperators(ast)...)
	
	return errors
}

func (p *Parser) validateCommandStructure(node *models.ASTNode) []string {
	var errors []string
	
	if node.Type == "Command" {
		hasCommandName := false
		for _, child := range node.Children {
			if child.Type == "CommandName" {
				hasCommandName = true
				break
			}
		}
		if !hasCommandName {
			errors = append(errors, "comando sin nombre válido")
		}
	}
	
	for _, child := range node.Children {
		errors = append(errors, p.validateCommandStructure(child)...)
	}
	
	return errors
}

func (p *Parser) validateRedirections(node *models.ASTNode) []string {
	var errors []string
	
	if node.Type == "Redirection" {
		if len(node.Children) == 0 {
			errors = append(errors, "redirección sin destino")
		} else {
			target := node.Children[0]
			if target.Type != "RedirectionTarget" {
				errors = append(errors, "destino de redirección inválido")
			}
		}
	}
	
	for _, child := range node.Children {
		errors = append(errors, p.validateRedirections(child)...)
	}
	
	return errors
}

func (p *Parser) validatePipes(node *models.ASTNode) []string {
	var errors []string
	
	if node.Type == "Pipeline" {
		commandCount := 0
		pipeCount := 0
		
		for _, child := range node.Children {
			if child.Type == "Command" {
				commandCount++
			} else if child.Type == "Pipe" {
				pipeCount++
			}
		}
		
		if pipeCount > 0 && commandCount != pipeCount+1 {
			errors = append(errors, "estructura de pipeline inválida")
		}
	}
	
	for _, child := range node.Children {
		errors = append(errors, p.validatePipes(child)...)
	}
	
	return errors
}

func (p *Parser) validateOperators(node *models.ASTNode) []string {
	var errors []string
	
	if node.Type == "LogicalOperator" {
		validOperators := map[string]bool{
			"&&": true,
			"||": true,
		}
		
		if !validOperators[node.Value] {
			errors = append(errors, fmt.Sprintf("operador lógico inválido: %s", node.Value))
		}
	}
	
	for _, child := range node.Children {
		errors = append(errors, p.validateOperators(child)...)
	}
	
	return errors
}

// DetectSuspiciousSyntax identifica patrones sintácticos sospechosos
func (p *Parser) DetectSuspiciousSyntax(ast *models.ASTNode) []string {
	var suspicious []string
	
	suspicious = append(suspicious, p.detectObfuscation(ast)...)
	suspicious = append(suspicious, p.detectChaining(ast)...)
	suspicious = append(suspicious, p.detectEvasion(ast)...)
	
	return suspicious
}

func (p *Parser) detectObfuscation(node *models.ASTNode) []string {
	var patterns []string
	
	// Detectar comandos con codificación
	if node.Type == "Argument" && node.Token != nil {
		if node.Token.Type == models.ENCODED {
			patterns = append(patterns, "argumento codificado detectado")
		}
	}
	
	// Detectar uso excesivo de variables
	if node.Type == "Command" {
		varCount := 0
		for _, child := range node.Children {
			if child.Token != nil && child.Token.Type == models.VARIABLE {
				varCount++
			}
		}
		if varCount > 3 {
			patterns = append(patterns, "uso excesivo de variables")
		}
	}
	
	for _, child := range node.Children {
		patterns = append(patterns, p.detectObfuscation(child)...)
	}
	
	return patterns
}

func (p *Parser) detectChaining(node *models.ASTNode) []string {
	var patterns []string
	
	if node.Type == "CommandLine" {
		commandCount := 0
		for _, child := range node.Children {
			if child.Type == "Pipeline" || child.Type == "Command" {
				commandCount++
			}
		}
		
		if commandCount > 5 {
			patterns = append(patterns, "cadena excesiva de comandos")
		}
	}
	
	for _, child := range node.Children {
		patterns = append(patterns, p.detectChaining(child)...)
	}
	
	return patterns
}

func (p *Parser) detectEvasion(node *models.ASTNode) []string {
	var patterns []string
	
	// Detectar redirecciones sospechosas
	if node.Type == "Redirection" && len(node.Children) > 0 {
		target := node.Children[0].Value
		if strings.Contains(target, "/dev/null") {
			patterns = append(patterns, "supresión de salida detectada")
		}
		if strings.Contains(target, "/dev/tcp/") {
			patterns = append(patterns, "conexión de red a través de redirección")
		}
	}
	
	// Detectar wildcards excesivos
	if node.Type == "Command" {
		wildcardCount := 0
		for _, child := range node.Children {
			if child.Token != nil && child.Token.Type == models.WILDCARD {
				wildcardCount++
			}
		}
		if wildcardCount > 2 {
			patterns = append(patterns, "uso excesivo de wildcards")
		}
	}
	
	for _, child := range node.Children {
		patterns = append(patterns, p.detectEvasion(child)...)
	}
	
	return patterns
}