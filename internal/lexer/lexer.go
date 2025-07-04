package lexer

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"security-monitor/internal/models"
)

type Lexer struct {
	input        string
	position     int  // posición actual en input
	readPosition int  // posición de lectura actual
	ch           byte // carácter actual bajo examinación
	line         int  // línea actual
	column       int  // columna actual
}

func New() *Lexer {
	return &Lexer{
		line:   1,
		column: 0,
	}
}

func (l *Lexer) Tokenize(input string) ([]models.Token, error) {
	l.input = input
	l.position = 0
	l.readPosition = 0
	l.line = 1
	l.column = 0
	l.readChar()

	var tokens []models.Token

	for {
		l.skipWhitespace()
		
		if l.ch == 0 {
			tokens = append(tokens, models.Token{
				Type:     models.EOF,
				Value:    "",
				Position: l.position,
				Line:     l.line,
				Column:   l.column,
			})
			break
		}

		token, err := l.nextToken()
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, token)
	}

	return l.normalizeTokens(tokens), nil
}

func (l *Lexer) nextToken() (models.Token, error) {
	var token models.Token

	token.Position = l.position
	token.Line = l.line
	token.Column = l.column

	switch l.ch {
	case '|':
		if l.peekChar() == '|' {
			ch := l.ch
			l.readChar()
			token.Type = models.OPERATOR
			token.Value = string(ch) + string(l.ch)
		} else {
			token.Type = models.PIPE
			token.Value = string(l.ch)
		}
	case '>':
		if l.peekChar() == '>' {
			ch := l.ch
			l.readChar()
			token.Type = models.REDIRECT
			token.Value = string(ch) + string(l.ch)
		} else {
			token.Type = models.REDIRECT
			token.Value = string(l.ch)
		}
	case '<':
		token.Type = models.REDIRECT
		token.Value = string(l.ch)
	case '&':
		if l.peekChar() == '&' {
			ch := l.ch
			l.readChar()
			token.Type = models.OPERATOR
			token.Value = string(ch) + string(l.ch)
		} else {
			token.Type = models.AMPERSAND
			token.Value = string(l.ch)
		}
	case ';':
		token.Type = models.SEMICOLON
		token.Value = string(l.ch)
	case '"':
		token.Type = models.STRING
		token.Value = l.readString('"')
	case '\'':
		token.Type = models.STRING
		token.Value = l.readString('\'')
	case '$':
		token.Type = models.VARIABLE
		token.Value = l.readVariable()
	case '*', '?', '[', ']':
		token.Type = models.WILDCARD
		token.Value = string(l.ch)
	default:
		if unicode.IsLetter(rune(l.ch)) || l.ch == '_' || l.ch == '/' || l.ch == '.' || l.ch == '-' {
			identifier := l.readIdentifier()
			token.Value = identifier
			token.Type = l.determineTokenType(identifier)
		} else if unicode.IsDigit(rune(l.ch)) {
			token.Type = models.NUMBER
			token.Value = l.readNumber()
		} else {
			token.Type = models.SPECIAL_CHAR
			token.Value = string(l.ch)
		}
	}

	l.readChar()
	return token, nil
}

func (l *Lexer) determineTokenType(identifier string) models.TokenType {
	// Verificar si es una ruta
	if l.isPath(identifier) {
		return models.PATH
	}

	// Verificar si es una dirección IP
	if l.isIPAddress(identifier) {
		return models.IP_ADDRESS
	}

	// Verificar si es una URL
	if l.isURL(identifier) {
		return models.URL
	}

	// Verificar si está codificado
	if l.isEncoded(identifier) {
		return models.ENCODED
	}

	// Verificar si es un flag (empieza con -)
	if strings.HasPrefix(identifier, "-") {
		return models.FLAG
	}

	// Verificar si es un comando conocido
	if l.isKnownCommand(identifier) {
		return models.COMMAND
	}

	// Por defecto, es un parámetro
	return models.PARAMETER
}

func (l *Lexer) isPath(s string) bool {
	pathPatterns := []string{
		`^/[a-zA-Z0-9._/-]*`,           // Ruta absoluta
		`^\.{1,2}/[a-zA-Z0-9._/-]*`,    // Ruta relativa
		`^~[a-zA-Z0-9._/-]*`,           // Ruta home
		`.*\.[a-zA-Z0-9]+$`,            // Archivo con extensión
	}

	for _, pattern := range pathPatterns {
		if matched, _ := regexp.MatchString(pattern, s); matched {
			return true
		}
	}

	return false
}

func (l *Lexer) isIPAddress(s string) bool {
	ipPattern := `^(\d{1,3}\.){3}\d{1,3}(:\d+)?$`
	matched, _ := regexp.MatchString(ipPattern, s)
	return matched
}

func (l *Lexer) isURL(s string) bool {
	urlPattern := `^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`
	matched, _ := regexp.MatchString(urlPattern, s)
	return matched
}

func (l *Lexer) isEncoded(s string) bool {
	// Verificar Base64
	if l.isBase64(s) {
		return true
	}

	// Verificar Hexadecimal
	if l.isHex(s) {
		return true
	}

	return false
}

func (l *Lexer) isBase64(s string) bool {
	if len(s) < 4 || len(s)%4 != 0 {
		return false
	}

	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func (l *Lexer) isHex(s string) bool {
	if len(s) < 2 || len(s)%2 != 0 {
		return false
	}

	_, err := hex.DecodeString(s)
	return err == nil && len(s) > 10 // Solo considerar hex largo como codificado
}

func (l *Lexer) isKnownCommand(s string) bool {
	// Lista completa con COMANDOS CRÍTICOS al principio
	commands := map[string]bool{
		// COMANDOS CRÍTICOS PRIMERO - GARANTIZADO
		"sudo": true, "su": true, "passwd": true,
		"find": true, "curl": true, "wget": true,
		"nc": true, "ncat": true, "netcat": true,
		
		// Comandos de sistema básicos
		"ls": true, "cat": true, "grep": true, "ps": true,
		"top": true, "htop": true, "netstat": true, "ss": true, "lsof": true,
		"whoami": true, "id": true, "uname": true, "hostname": true,
		
		// Comandos de red
		"ping": true, "ssh": true, "scp": true, "rsync": true, "telnet": true,
		
		// Comandos de archivos
		"chmod": true, "chown": true, "cp": true, "mv": true, "rm": true,
		"mkdir": true, "rmdir": true, "touch": true, "ln": true,
		
		// Comandos de usuarios
		"useradd": true, "userdel": true, "usermod": true, "groups": true, "newgrp": true,
		
		// Comandos de procesos
		"kill": true, "killall": true, "nohup": true, "screen": true, "tmux": true,
		
		// Comandos de archivado
		"tar": true, "gzip": true, "gunzip": true, "zip": true, "unzip": true,
		
		// Comandos de monitoreo
		"tail": true, "head": true, "less": true, "more": true, "watch": true,
		
		// Comandos de sistema
		"mount": true, "umount": true, "df": true, "du": true, "free": true,
		"crontab": true, "systemctl": true, "service": true, "chkconfig": true,
		
		// Comandos de red avanzados
		"iptables": true, "nmap": true, "tcpdump": true, "wireshark": true,
		"arp": true, "route": true, "ip": true, "ifconfig": true,
		
		// Comandos adicionales importantes
		"echo": true, "printf": true, "test": true, "bash": true, "sh": true,
		"awk": true, "sed": true, "sort": true, "uniq": true, "cut": true,
		"tr": true, "wc": true, "xargs": true, "tee": true, "diff": true,
		"which": true, "whereis": true, "locate": true, "updatedb": true,
		"history": true, "alias": true, "unalias": true, "export": true,
		"env": true, "printenv": true, "set": true, "unset": true,
		"jobs": true, "fg": true, "bg": true, "disown": true,
		"clear": true, "reset": true, "date": true, "cal": true,
		"uptime": true, "w": true, "who": true, "last": true,
		"vim": true, "vi": true, "nano": true, "emacs": true,
		"make": true, "gcc": true, "python": true, "python3": true,
		"git": true, "docker": true, "kubectl": true,
		"mysql": true, "psql": true, "sqlite3": true,
		"apache2": true, "nginx": true, "httpd": true,
		"base64": true, "openssl": true, "gpg": true,
		"md5sum": true, "sha1sum": true, "sha256sum": true,
		"dd": true, "hexdump": true, "strings": true, "xxd": true,
		"strace": true, "ltrace": true, "gdb": true,
		"john": true, "hashcat": true, "hydra": true,
		"metasploit": true, "msfconsole": true, "msfvenom": true,
		"aircrack-ng": true, "nikto": true, "dirb": true,
		"gobuster": true, "ffuf": true, "wfuzz": true,
		"sqlmap": true, "burpsuite": true, "nessus": true,
		"volatility": true, "autopsy": true, "binwalk": true,
		"foremost": true, "photorec": true, "testdisk": true,
		"chkrootkit": true, "rkhunter": true, "lynis": true,
		"fail2ban": true, "aide": true, "tripwire": true,
		"clamav": true, "freshclam": true, "maldet": true,
		"socat": true, "stunnel": true, "openvpn": true,
		"tor": true, "proxychains": true, "steghide": true,
		"exiftool": true, "yara": true, "masscan": true,
		"zmap": true, "hping3": true, "ettercap": true,
		"bettercap": true, "mitmproxy": true, "dsniff": true,
		"tcpkill": true, "scapy": true, "ncrack": true,
		"medusa": true, "patator": true, "wpscan": true,
		"joomscan": true, "droopescan": true, "cmseek": true,
		"whatweb": true, "webtech": true, "sublist3r": true,
		"amass": true, "subfinder": true, "assetfinder": true,
		"findomain": true, "knockpy": true, "dnsrecon": true,
		"fierce": true, "dnsmap": true, "theharvester": true,
		"maltego": true, "recon-ng": true, "spiderfoot": true,
		"shodan": true, "censys": true, "rustscan": true,
		"naabu": true, "sx": true, "unicornscan": true,
	}

	// Verificación adicional para comandos críticos específicamente
	criticalCommands := []string{"sudo", "su", "find", "curl", "wget", "nc", "ncat", "chmod"}
	for _, cmd := range criticalCommands {
		if s == cmd {
			return true
		}
	}

	return commands[s]
}

func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0 // ASCII NUL character representa EOF
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition++
	
	if l.ch == '\n' {
		l.line++
		l.column = 0
	} else {
		l.column++
	}
}

func (l *Lexer) peekChar() byte {
	if l.readPosition >= len(l.input) {
		return 0
	}
	return l.input[l.readPosition]
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

func (l *Lexer) readIdentifier() string {
	position := l.position
	for unicode.IsLetter(rune(l.ch)) || unicode.IsDigit(rune(l.ch)) || l.ch == '_' || 
		  l.ch == '-' || l.ch == '.' || l.ch == '/' || l.ch == ':' || l.ch == '=' {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readNumber() string {
	position := l.position
	for unicode.IsDigit(rune(l.ch)) || l.ch == '.' {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readString(delimiter byte) string {
	position := l.position + 1
	for {
		l.readChar()
		if l.ch == delimiter || l.ch == 0 {
			break
		}
	}
	return l.input[position:l.position]
}

func (l *Lexer) readVariable() string {
	position := l.position
	l.readChar()
	if l.ch == '{' {
		for l.ch != '}' && l.ch != 0 {
			l.readChar()
		}
		if l.ch == '}' {
			l.readChar()
		}
	} else {
		for unicode.IsLetter(rune(l.ch)) || unicode.IsDigit(rune(l.ch)) || l.ch == '_' {
			l.readChar()
		}
	}
	return l.input[position:l.position]
}

func (l *Lexer) normalizeTokens(tokens []models.Token) []models.Token {
	normalized := make([]models.Token, 0, len(tokens))
	
	for _, token := range tokens {
		// Normalizar aliases de comandos
		if token.Type == models.COMMAND {
			token.Value = l.normalizeCommand(token.Value)
		}
		
		// Detectar puertos en direcciones IP
		if token.Type == models.IP_ADDRESS && strings.Contains(token.Value, ":") {
			parts := strings.Split(token.Value, ":")
			if len(parts) == 2 {
				// Dividir IP y puerto
				ipToken := token
				ipToken.Value = parts[0]
				ipToken.Type = models.IP_ADDRESS
				
				portToken := token
				portToken.Value = parts[1]
				portToken.Type = models.PORT
				portToken.Position = token.Position + len(parts[0]) + 1
				
				normalized = append(normalized, ipToken, portToken)
				continue
			}
		}
		
		normalized = append(normalized, token)
	}
	
	return normalized
}

func (l *Lexer) normalizeCommand(command string) string {
	aliases := map[string]string{
		"ll":     "ls",
		"la":     "ls",
		"l":      "ls",
		"dir":    "ls",
		"copy":   "cp",
		"move":   "mv",
		"del":    "rm",
		"type":   "cat",
		"cls":    "clear",
		"md":     "mkdir",
		"rd":     "rmdir",
	}
	
	if normalized, exists := aliases[command]; exists {
		return normalized
	}
	
	return command
}