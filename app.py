from flask import Flask, jsonify, request, make_response
from datetime import datetime, timedelta
import time

app = Flask(__name__)

# --- SISTEMA DE LOGINS (RBAC) ---
USUARIOS = {
    "admin": {"senha": "100110Md.", "role": "admin"},
    "cliente": {"senha": "cliente123", "role": "viewer"}
}

def get_user_role(req):
    user = req.headers.get('X-Auth-User')
    pwd = req.headers.get('X-Auth-Pass')
    if user in USUARIOS and USUARIOS[user]['senha'] == pwd:
        return USUARIOS[user]['role']
    return None

@app.before_request
def require_auth():
    rotas_abertas = ['/', '/api/login', '/api/receber_dados', '/api/receber_scan', '/api/receber_logs', '/manifest.json', '/sw.js']
    if request.path in rotas_abertas:
        return
    role = get_user_role(request)
    if not role:
        return jsonify({"error": "Unauthorized"}), 401
    request.user_role = role

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.json
    u = data.get('user')
    p = data.get('pass')
    if u in USUARIOS and USUARIOS[u]['senha'] == p:
        return jsonify({"status": "success", "role": USUARIOS[u]['role']})
    return jsonify({"status": "error"}), 401

# --- BANCO DE DADOS EM MEMÓRIA ---
sensores_conectados = {}
comandos_pendentes = {} 
resultados_scan = {}
resultados_logs = {} 
eventos_criticos = [] 

def registrar_alerta(sensor_id, msg, level="warning"):
    ultimos_deste_sensor = [e for e in eventos_criticos if e["sensor_id"] == sensor_id]
    if ultimos_deste_sensor:
        ultimo_msg = ultimos_deste_sensor[-1]["msg"]
        if msg in ultimo_msg or ultimo_msg in msg:
            return
    hora_brasil = datetime.utcnow() - timedelta(hours=3)
    eventos_criticos.append({
        "time": hora_brasil.strftime("%d/%m %H:%M:%S"),
        "sensor_id": sensor_id,
        "msg": msg,
        "level": level
    })
    if len(eventos_criticos) > 50:
        eventos_criticos.pop(0)

@app.route('/api/receber_dados', methods=['POST'])
def receber_dados():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    if sensor_id:
        sensores_conectados[sensor_id] = {"last_ping": time.time(), "data": payload}
        diag = payload.get("diagnostics", "")
        if any(palavra in diag for palavra in ["LOOP", "FALHA", "SEM INTERNET", "INSTABILIDADE"]):
            nivel = "error" if "FALHA" in diag or "LOOP" in diag else "warning"
            registrar_alerta(sensor_id, diag, nivel)
        
    comando = comandos_pendentes.pop(sensor_id, None)
    return jsonify({"status": "sucesso", "comando": comando})

@app.route('/api/receber_scan', methods=['POST'])
def receber_scan():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    resultados_scan[sensor_id] = payload.get("devices", [])
    return jsonify({"status": "recebido"})

@app.route('/api/receber_logs', methods=['POST'])
def receber_logs():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    resultados_logs[sensor_id] = payload.get("logs", [])
    return jsonify({"status": "recebido"})

@app.route('/api/sensores')
def get_sensores():
    agora = time.time()
    ativos = {}
    for s_id, s_data in list(sensores_conectados.items()):
        if agora - s_data['last_ping'] < 15:
            ativos[s_id] = s_data
        else:
            registrar_alerta(s_id, f"🔴 SENSOR DESCONECTADO (Máquina desligada ou sem internet).", "error")
    sensores_conectados.clear()
    sensores_conectados.update(ativos)
    return jsonify({"sensores": sensores_conectados, "alertas": list(reversed(eventos_criticos))})

@app.route('/api/limpar_alertas', methods=['POST'])
def limpar_alertas():
    if getattr(request, 'user_role', None) == 'admin': 
        eventos_criticos.clear()
    return jsonify({"status": "limpo"})

@app.route('/api/enviar_comando', methods=['POST'])
def enviar_comando():
    if getattr(request, 'user_role', None) != 'admin':
        return jsonify({"status": "erro", "msg": "Sem permissão"}), 403
        
    dados = request.json
    sensor_id = dados.get("sensor_id")
    comando = dados.get("comando")
    
    pacote = {"comando": comando}
    if comando == "UPDATE_CONFIG":
        pacote["router_ip"] = dados.get("router_ip")
        pacote["external_targets"] = dados.get("external_targets")
    elif comando == "GET_LOGS":
        pacote["period"] = dados.get("period")
        pacote["date"] = dados.get("date")
        
    comandos_pendentes[sensor_id] = pacote
    if comando == "SCAN": resultados_scan.pop(sensor_id, None) 
    if comando == "GET_LOGS": resultados_logs.pop(sensor_id, None) 
    return jsonify({"status": "enviado"})

@app.route('/api/ler_scan')
def ler_scan():
    sensor_id = request.args.get("sensor_id")
    if sensor_id in resultados_scan: return jsonify({"status": "pronto", "devices": resultados_scan[sensor_id]})
    return jsonify({"status": "aguardando"})

@app.route('/api/ler_logs')
def ler_logs():
    sensor_id = request.args.get("sensor_id")
    if sensor_id in resultados_logs: return jsonify({"status": "pronto", "logs": resultados_logs[sensor_id]})
    return jsonify({"status": "aguardando"})

# --- ROTAS DO PWA ---
@app.route('/manifest.json')
def serve_manifest():
    manifest = {
        "name": "Network Analyzer PRO - Central", "short_name": "NetAnalyzer", "start_url": "/", "display": "standalone", "orientation": "any",  
        "background_color": "#1e1e2e", "theme_color": "#89b4fa",
        "icons": [{"src": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iIzFlMWUyZSIvPjxjaXJjbGUgY3g9IjUwIiBjeT0iNTAiIHI9IjQwIiBmaWxsPSJub25lIiBzdHJva2U9IiM4OWI0ZmEiIHN0cm9rZS13aWR0aD0iOCIvPjxwb2x5bGluZSBwb2ludHM9IjMwLDUwIDQ1LDY1IDcwLDM1IiBmaWxsPSJub25lIiBzdHJva2U9IiNhNmUzYTEiIHN0cm9rZS13aWR0aD0iOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PC9zdmc+", "sizes": "192x192", "type": "image/svg+xml"}]
    }
    return jsonify(manifest)

@app.route('/sw.js')
def serve_sw():
    sw_code = "self.addEventListener('install', (e) => { self.skipWaiting(); }); self.addEventListener('activate', (e) => { e.waitUntil(clients.claim()); }); self.addEventListener('fetch', (e) => { e.respondWith(fetch(e.request)); });"
    response = make_response(sw_code)
    response.headers['Content-Type'] = 'application/javascript'
    return response

# --- FRONT-END CENTRAL ---
@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Network Analyzer PRO - Central</title>
        <link rel="manifest" href="/manifest.json">
        <meta name="theme-color" content="#89b4fa">
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js"></script>
        
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }
            #login-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(30, 30, 46, 0.95); z-index: 10000; display: flex; justify-content: center; align-items: center; backdrop-filter: blur(10px); }
            .login-box { background: #313244; padding: 40px; border-radius: 12px; box-shadow: 0 15px 35px rgba(0,0,0,0.5); border: 2px solid #89b4fa; width: 320px; text-align: center; }
            .login-box input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #45475a; border-radius: 6px; background: #1e1e2e; color: #cdd6f4; box-sizing: border-box; font-size: 1.1em;}
            .btn-login { width: 100%; padding: 12px; font-size: 1.1em; background: #a6e3a1; color:#1e1e2e; border:none; border-radius:4px; font-weight:bold; cursor:pointer; transition:0.2s;}
            .btn-login:hover { background: #94e2d5; }
            #main-content { display: none; }
            
            .noc-layout { display: grid; grid-template-columns: 3fr 1fr; gap: 20px; max-width: 1500px; margin: 0 auto; align-items: start;}
            .main-panel { background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            .side-panel { background: #1e1e2e; display: flex; flex-direction: column; gap: 15px; position: sticky; top: 15px; align-self: start; }
            @media (max-width: 900px) { .noc-layout { grid-template-columns: 1fr; } .side-panel { position: static; } }
            
            h1 { color: #89b4fa; text-align: center; margin-top: 0; }
            .brand-header { text-align: center; font-size: 0.75em; color: #6c7086; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 5px; font-weight: bold; }
            
            .global-alerts-container { background: #181825; border-left: 4px solid #f38ba8; padding: 15px; border-radius: 8px; margin-bottom: 20px; max-height: 250px; overflow-y: auto; }
            .alerts-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .btn-clear-alerts { background: #45475a; color: #cdd6f4; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 0.8em; }
            .alert-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
            .alert-table th, .alert-table td { padding: 8px; border-bottom: 1px solid #313244; text-align: left; }
            .alert-table th { color: #bac2de; position: sticky; top: 0; background: #181825; }
            .alert-error { color: #f38ba8; font-weight: bold; }
            .alert-warning { color: #f9e2af; font-weight: bold; }
            .sensor-badge { background: #313244; padding: 3px 8px; border-radius: 4px; color: #89b4fa; font-family: monospace; font-size: 0.9em; }
            
            .selector-container { background: #181825; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; border: 2px solid #a6e3a1; display:flex; justify-content: space-between; align-items: center;}
            select { padding: 10px; font-size: 1.1em; border-radius: 4px; background: #1e1e2e; color: #a6e3a1; font-weight: bold; border: 1px solid #45475a; min-width: 300px; cursor: pointer; flex: 1; margin: 0 15px;}
            @media (max-width: 600px) { .selector-container { flex-direction: column; gap: 10px; } select { width: 100%; margin: 0; } }
            
            .status-box { padding: 15px; margin: 15px 0; border-radius: 5px; font-weight: bold; text-align: center; font-size: 1.1em;}
            .ok { background-color: #a6e3a1; color: #1e1e2e; }
            .error { background-color: #f38ba8; color: #1e1e2e; }
            .warning { background-color: #f9e2af; color: #1e1e2e; }
            
            .targets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; margin-bottom: 20px;}
            .target-card { background: #181825; padding: 10px; border-radius: 6px; text-align: center; border-left: 4px solid #45475a;}
            .target-card.online { border-left-color: #a6e3a1; }
            .target-card.offline { border-left-color: #f38ba8; }
            
            .chart-container { position: relative; height: 300px; width: 100%; margin-bottom: 20px; background: #181825; padding: 15px; border-radius: 8px; box-sizing: border-box;}
            .offline-msg { text-align: center; color: #f38ba8; font-size: 1.2em; margin: 50px 0; display: none;}
            
            .global-card { background: #313244; padding: 10px 15px; border-radius: 8px; border-left: 3px solid #89b4fa;}
            .global-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;}
            .global-ms { font-family: monospace; font-size: 1.1em; color: #a6e3a1;}
            
            button { padding: 10px 15px; font-weight: bold; border: none; border-radius: 4px; cursor: pointer; width: 100%; margin-bottom: 10px; transition: 0.2s;}
            .btn-scan { background: #a6e3a1; color: #1e1e2e; }
            .btn-scan:hover { background: #94e2d5; }
            .btn-logs { background: #cba6f7; color: #1e1e2e; margin-bottom:0;}
            .btn-logs:hover { background: #b4befe; }
            .btn-danger { background: #f38ba8; color: #1e1e2e; }
            .btn-danger:hover { background: #eba0ac; }
            .btn-save { background: #89b4fa; color: #1e1e2e; }
            .btn-save:hover { background: #b4befe; }
            .btn-save:disabled { background: #6c7086; cursor: not-allowed; }
            
            #scanner-modal { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center;}
            .modal-content { background: #313244; padding: 20px; border-radius: 8px; width: 80%; max-width: 800px; max-height: 80vh; overflow-y: auto;}
            .close-btn { float: right; cursor: pointer; color: #f38ba8; font-weight: bold; font-size: 1.2em;}
            table { width: 100%; border-collapse: collapse; margin-top: 15px; } th, td { padding: 10px; border-bottom: 1px solid #45475a; text-align: left; } th { color: #bac2de; }
            
            .input-group { display: flex; flex-direction: column; flex: 1; min-width: 150px; text-align:left;}
            .input-group label { margin-bottom: 5px; font-size: 0.85em; color: #bac2de; font-weight: bold;}
            input[type="text"], input[type="date"] { padding: 8px; border: 1px solid #45475a; border-radius: 4px; background: #1e1e2e; color: #cdd6f4; width: 95%; box-sizing: border-box;}

            .pwa-popup { display: none; position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: #313244; padding: 20px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); border: 2px solid #89b4fa; z-index: 9999; text-align: center; width: 90%; max-width: 400px;}
            .pwa-popup p { margin: 0 0 15px 0; color: #cdd6f4; font-weight: bold; font-size: 1.1em; }
            .btn-install-pwa { background: #a6e3a1; color: #1e1e2e; width: 48%; margin: 0; }
            .btn-close-pwa { background: #45475a; color: #cdd6f4; width: 48%; margin: 0; }
            .box-forense { background: #181825; padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 3px solid #cba6f7;}
        </style>
    </head>
    <body>
        
        <div id="login-overlay">
            <div class="login-box">
                <div class="brand-header" style="margin-bottom:20px;">MD Soluções Tecnológicas</div>
                <h2 style="color: #a6e3a1; margin-top:0;">NOC Central</h2>
                <input type="text" id="login-user" placeholder="Usuário" autocomplete="off">
                <input type="password" id="login-pass" placeholder="Senha" autocomplete="off" onkeypress="if(event.key === 'Enter') doLogin();">
                <button class="btn-login" onclick="doLogin()">Acessar Painel</button>
                <p id="login-err" style="color: #f38ba8; font-size: 0.9em; display: none;">Credenciais Inválidas.</p>
            </div>
        </div>

        <div id="pwa-install-popup" class="pwa-popup">
            <p>📲 Deseja instalar o Network Analyzer PRO no seu celular?</p>
            <div style="display: flex; justify-content: space-between;">
                <button id="btn-close-pwa" class="btn-close-pwa">Agora Não</button>
                <button id="btn-install-pwa" class="btn-install-pwa">Instalar App</button>
            </div>
        </div>

        <div id="scanner-modal">
            <div class="modal-content">
                <span class="close-btn" onclick="document.getElementById('scanner-modal').style.display='none'">✖ Fechar</span>
                <h2 style="color:#a6e3a1; margin-top:0;" id="modal-title">⏳ Executando Ordem Remota...</h2>
                <div id="scanner-results"><p style="text-align:center;">Aguardando o Sensor...</p></div>
            </div>
        </div>

        <div id="main-content">
            <div class="noc-layout">
                <div class="main-panel">
                    <div class="brand-header">MD Soluções Tecnológicas</div>
                    <h1>🌐 Network Analyzer PRO - Central</h1>
                    
                    <div class="global-alerts-container">
                        <div class="alerts-header">
                            <h3 style="margin: 0; color: #f38ba8; font-size:1.1em;">🚨 Radar Global</h3>
                            <button id="btn-clear-alerts" class="btn-clear-alerts" onclick="limparAlertasGlobais()" style="display:none; width:auto; margin:0;">Varrer Histórico</button>
                        </div>
                        <table class="alert-table">
                            <thead><tr><th style="width: 25%;">Hora</th><th style="width: 25%;">Máquina</th><th>Incidente</th></tr></thead>
                            <tbody id="global-alerts-body">
                                <tr><td colspan="3" style="text-align:center; color:#6c7086;">Nenhuma falha detectada.</td></tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="selector-container">
                        <div id="role-badge" style="font-size:0.8em; padding:5px 10px; background:#45475a; border-radius:4px; font-weight:bold;"></div>
                        <select id="sensor-select" onchange="changeSensor()">
                            <option value="">Aguardando conexão de sensores...</option>
                        </select>
                    </div>

                    <div id="offline-alert" class="offline-msg">⚠️ Nenhum Sensor Selecionado ou Máquina Offline.</div>

                    <div id="dashboard-content" style="display:none;">
                        
                        <div id="admin-config-panel" style="background: #181825; padding: 15px; border-radius: 8px; margin-bottom: 20px; display:none;">
                            <h4 style="margin: 0 0 15px 0; color:#89b4fa;">⚙️ Alterar Configurações Remotamente</h4>
                            <div style="display: flex; gap: 15px; align-items: flex-end; flex-wrap: wrap;">
                                <div class="input-group">
                                    <label>Gateway / Roteador</label>
                                    <input type="text" id="remote-router" placeholder="Ex: 192.168.0.1">
                                </div>
                                <div class="input-group" style="flex:2;">
                                    <label>Alvos a Monitorar</label>
                                    <input type="text" id="remote-externals" placeholder="Ex: google.com, 8.8.8.8">
                                </div>
                                <button id="btn-aplicar" class="btn-save" onclick="enviarNovaConfig()" style="width: 100%; margin-bottom:0; margin-top: 10px;">💾 Aplicar Mudanças</button>
                            </div>
                        </div>

                        <div id="diag-box" class="status-box ok">Conectando...</div>
                        <div class="targets-grid" id="targets-container"></div>
                        <h4 style="color:#bac2de; margin-bottom: 5px;">Latências da Rede Local</h4>
                        <div class="chart-container"><canvas id="mainChart"></canvas></div>
                    </div>
                </div>
                
                <div class="side-panel" id="sidebar-container" style="display:none;">
                    <div id="admin-c2-panel" style="display:none;">
                        
                        <div class="global-card" style="border-left-color: #f9e2af; margin-bottom: 15px;">
                            <h4 style="margin: 0 0 10px 0; color:#cdd6f4; text-align:center;">Comandos da Rede</h4>
                            <button class="btn-scan" onclick="enviarComando('SCAN')">🔍 Escanear Rede Local</button>
                        </div>
                        
                        <div class="box-forense">
                            <h4 style="margin: 0 0 10px 0; color:#cdd6f4; text-align:center;">Relatórios (B.I.)</h4>
                            <label style="font-size:0.8em; color:#bac2de; display:block; margin-bottom:5px;">Período do PDF:</label>
                            <select id="log-period" onchange="toggleDateInput()" style="width: 100%; margin:0 0 10px 0; padding: 8px; font-size: 0.9em;">
                                <option value="1">Hoje (Últimas 24h)</option>
                                <option value="7">Últimos 7 Dias</option>
                                <option value="15">Últimos 15 Dias</option>
                                <option value="30">Últimos 30 Dias (Tudo)</option>
                                <option value="custom">Data Específica...</option>
                            </select>
                            <input type="date" id="log-date" style="display:none; width: 100%; margin-bottom: 10px; padding: 8px; font-size: 0.9em; box-sizing: border-box;">
                            
                            <button class="btn-logs" style="width: 100%;" onclick="enviarComando('GET_LOGS')">📄 Extrair PDF</button>
                        </div>
                        
                        <div class="global-card" style="border-left-color: #f38ba8; margin-bottom: 15px;">
                            <button class="btn-danger" style="margin-bottom:0;" onclick="confirmarDesinstalacao()">🗑️ Auto-Destruir Sensor</button>
                        </div>
                        
                    </div>
                    
                    <h3 style="color: #bac2de; margin-bottom: 0; text-align:center;">🌐 Tráfego Global</h3>
                    <p style="font-size: 0.8em; text-align: center; color: #6c7086; margin-top:0;">Visão do cliente</p>
                    <div id="globals-container"></div>
                </div>
            </div>
        </div>

        <script>
            let deferredPrompt;
            if ('serviceWorker' in navigator) { window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js'); }); }
            window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredPrompt = e; document.getElementById('pwa-install-popup').style.display = 'block'; });
            document.getElementById('btn-close-pwa').addEventListener('click', () => { document.getElementById('pwa-install-popup').style.display = 'none'; });
            document.getElementById('btn-install-pwa').addEventListener('click', async () => { document.getElementById('pwa-install-popup').style.display = 'none'; if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; } });

            // --- VARIÁVEIS DE SESSÃO VOLÁTIL ---
            let authUser = ""; let authPass = ""; let userRole = ""; 
            let currentSensor = ""; let mainChart = null; let scanInterval = null; let logsInterval = null; let fetchInterval = null;
            let isConfigUpdating = false; // TRAVA DO EFEITO BUMERANGUE
            const colorPalette = ['#89b4fa', '#f9e2af', '#cba6f7', '#94e2d5', '#fab387', '#f38ba8'];

            async function doLogin() {
                const u = document.getElementById('login-user').value;
                const p = document.getElementById('login-pass').value;
                const err = document.getElementById('login-err');
                
                const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({user:u, pass:p}) });
                
                if(res.status === 200) {
                    const data = await res.json();
                    authUser = u; authPass = p; userRole = data.role;
                    
                    document.getElementById('login-overlay').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                    err.style.display = 'none';
                    
                    if(userRole === "admin") {
                        document.getElementById('role-badge').innerText = "👨‍💻 ADMIN"; 
                        document.getElementById('role-badge').style.color = "#a6e3a1";
                        document.getElementById('admin-config-panel').style.display = "block"; 
                        document.getElementById('admin-c2-panel').style.display = "block"; 
                        document.getElementById('btn-clear-alerts').style.display = "block";
                    } else {
                        document.getElementById('role-badge').innerText = "👁️ VIEWER"; 
                        document.getElementById('role-badge').style.color = "#f9e2af";
                    }
                    
                    initChart();
                    fetchMasterData();
                    fetchInterval = setInterval(fetchMasterData, 1000);
                } else { err.style.display = 'block'; }
            }

            function lockScreen() {
                authUser = ""; authPass = ""; userRole = "";
                document.getElementById('login-overlay').style.display = 'flex';
                document.getElementById('main-content').style.display = 'none';
                document.getElementById('login-pass').value = "";
                if(fetchInterval) clearInterval(fetchInterval);
            }

            function getHeaders() { return { 'Content-Type': 'application/json', 'X-Auth-User': authUser, 'X-Auth-Pass': authPass }; }
            
            function toggleDateInput() {
                const val = document.getElementById('log-period').value;
                document.getElementById('log-date').style.display = val === 'custom' ? 'block' : 'none';
            }

            function initChart() {
                if(mainChart) return;
                const ctx = document.getElementById('mainChart').getContext('2d');
                mainChart = new Chart(ctx, { type: 'line', data: { labels: [], datasets: [] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 }, scales: { y: { beginAtZero: true, grid: { color: '#45475a' } }, x: { grid: { color: '#45475a' } } }, plugins: { legend: { labels: { color: '#cdd6f4' } } } } });
            }

            function changeSensor() {
                currentSensor = document.getElementById('sensor-select').value;
                if(currentSensor) {
                    document.getElementById('dashboard-content').style.display = 'block'; document.getElementById('sidebar-container').style.display = 'flex'; document.getElementById('offline-alert').style.display = 'none';
                    fetchMasterData();
                } else {
                    document.getElementById('dashboard-content').style.display = 'none'; document.getElementById('sidebar-container').style.display = 'none'; document.getElementById('offline-alert').style.display = 'block';
                }
            }

            // FUNÇÃO ATUALIZADA - CONGELA O BUMERANGUE
            async function enviarNovaConfig() {
                if(!currentSensor) return;
                
                isConfigUpdating = true; // ATIVA A TRAVA
                const btn = document.getElementById('btn-aplicar');
                btn.innerText = "⏳ Aplicando na Usina...";
                btn.disabled = true;

                const r_ip = document.getElementById('remote-router').value;
                const e_tg = document.getElementById('remote-externals').value;
                const res = await fetch('/api/enviar_comando', { method: 'POST', headers: getHeaders(), body: JSON.stringify({sensor_id: currentSensor, comando: "UPDATE_CONFIG", router_ip: r_ip, external_targets: e_tg}) });
                
                if(res.status === 401) return lockScreen();
                
                // Dá 4 segundos para a Nuvem parar de "atualizar a caixa" enquanto o sensor obedece
                setTimeout(() => {
                    isConfigUpdating = false;
                    btn.innerText = "💾 Aplicar Mudanças";
                    btn.disabled = false;
                }, 4000);
            }
            
            async function enviarComando(cmd) {
                if(!currentSensor) return;
                let payload = {sensor_id: currentSensor, comando: cmd};
                
                if(cmd === 'GET_LOGS') {
                    const periodVal = document.getElementById('log-period').value;
                    const dateVal = document.getElementById('log-date').value;
                    if(periodVal === 'custom' && !dateVal) return alert("Por favor, selecione uma data no calendário!");
                    payload.period = periodVal; payload.date = dateVal;
                }
                
                const res = await fetch('/api/enviar_comando', { method: 'POST', headers: getHeaders(), body: JSON.stringify(payload) });
                if(res.status === 401) return lockScreen();
                
                if(cmd === 'SCAN') {
                    document.getElementById('modal-title').innerText = "🔍 Scanner Remoto";
                    document.getElementById('scanner-modal').style.display = 'flex';
                    document.getElementById('scanner-results').innerHTML = '<p style="text-align:center; color:#a6e3a1;">Ordem enviada! Aguardando o Sensor varrer a rede local...</p>';
                    if(scanInterval) clearInterval(scanInterval); scanInterval = setInterval(verificarScan, 2000);
                }
                if(cmd === 'GET_LOGS') {
                    document.getElementById('modal-title').innerText = "📄 Extração Forense Remota";
                    document.getElementById('scanner-modal').style.display = 'flex';
                    document.getElementById('scanner-results').innerHTML = '<p style="text-align:center; color:#cba6f7;">Avisando o Sensor para ler o Banco de Dados... O PDF será gerado automaticamente.</p>';
                    if(logsInterval) clearInterval(logsInterval); logsInterval = setInterval(verificarLogs, 2000);
                }
            }

            async function verificarLogs() {
                const res = await fetch('/api/ler_logs?sensor_id=' + currentSensor, { headers: getHeaders() });
                if(res.status === 401) return lockScreen();
                const data = await res.json();
                if(data.status === "pronto") {
                    clearInterval(logsInterval);
                    document.getElementById('scanner-modal').style.display = 'none';
                    gerarPDF(data.logs);
                }
            }

            async function gerarPDF(logsData) {
                if(logsData.length === 0) return alert("O banco de dados da Usina não possui eventos de erro neste período.");
                const { jsPDF } = window.jspdf; const doc = new jsPDF('landscape');
                doc.setFillColor(49, 50, 68); doc.rect(0, 0, doc.internal.pageSize.width, 25, 'F');
                doc.setTextColor(255, 255, 255); doc.setFontSize(16); doc.setFont("helvetica", "bold");
                doc.text(`Network Analyzer PRO - Relatorio Forense [${currentSensor}]`, 14, 16);
                
                const tableData = logsData.map(log => {
                    let cleanMessage = log.message.replace(/\[Status no momento: (.*?)\]/g, '\\n>> Latências: $1');
                    return [log.time, log.level.toUpperCase(), cleanMessage];
                });
                doc.autoTable({
                    startY: 35, head: [['Data / Hora', 'Nível', 'Descrição do Evento (Registrado Localmente)']], body: tableData, theme: 'grid',
                    styles: { fontSize: 9, cellPadding: 3 }, headStyles: { fillColor: [49, 50, 68] },
                    willDrawCell: function (data) {
                        if (data.section === 'body' && data.column.index === 1) {
                            if (data.cell.raw === 'ERROR') doc.setTextColor(220, 53, 69);
                            else if (data.cell.raw === 'WARNING') doc.setTextColor(253, 126, 20);
                            else doc.setTextColor(13, 110, 253);
                        }
                        if (data.section === 'body' && data.column.index === 2) doc.setTextColor(60);
                    }
                });
                doc.save(`Relatorio_${currentSensor}.pdf`);
            }

            function confirmarDesinstalacao() {
                if(confirm("⚠️ ATENÇÃO EXTREMA!\\n\\nDeseja explodir o sensor remotamente?")) {
                    enviarComando('UNINSTALL');
                    alert("Ordem de Auto-destruição enviada.");
                }
            }

            async function limparAlertasGlobais() { 
                const res = await fetch('/api/limpar_alertas', { method: 'POST', headers: getHeaders() }); 
                if(res.status === 401) lockScreen();
            }

            async function verificarScan() {
                const res = await fetch('/api/ler_scan?sensor_id=' + currentSensor, { headers: getHeaders() });
                if(res.status === 401) return lockScreen();
                const data = await res.json();
                if(data.status === "pronto") {
                    clearInterval(scanInterval);
                    let html = `<table><thead><tr><th>IP Encontrado</th><th>Hostname</th></tr></thead><tbody>`;
                    data.devices.forEach(d => html += `<tr><td style="color:#a6e3a1; font-weight:bold;">${d.ip}</td><td>${d.hostname}</td></tr>`);
                    html += `</tbody></table><p style="text-align:right; font-size:0.8em; color:#a6adc8;">Total: ${data.devices.length} disp.</p>`;
                    document.getElementById('scanner-results').innerHTML = html;
                }
            }

            async function fetchMasterData() {
                try {
                    const res = await fetch('/api/sensores', { headers: getHeaders() });
                    if(res.status === 401) return lockScreen();
                    
                    const masterData = await res.json();
                    const sensores_dados = masterData.sensores || {};
                    const alertas_dados = masterData.alertas || [];
                    
                    const alertasTbody = document.getElementById('global-alerts-body');
                    if(alertas_dados.length === 0) { alertasTbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#a6e3a1; font-weight:bold;">Tudo OK! Nenhuma falha detectada.</td></tr>';
                    } else {
                        alertasTbody.innerHTML = '';
                        alertas_dados.forEach(alerta => {
                            const corClasse = alerta.level === 'error' ? 'alert-error' : 'alert-warning';
                            alertasTbody.innerHTML += `<tr><td>${alerta.time}</td><td><span class="sensor-badge">${alerta.sensor_id}</span></td><td class="${corClasse}">${alerta.msg}</td></tr>`;
                        });
                    }

                    const select = document.getElementById('sensor-select');
                    const oldVal = select.value;
                    let optionsHTML = '<option value="">-- Selecione uma Máquina --</option>';
                    for(const s_id in sensores_dados) optionsHTML += `<option value="${s_id}">🟢 Online: ${s_id}</option>`;
                    if(Object.keys(sensores_dados).length === 0) optionsHTML = '<option value="">🔴 Nenhum sensor online</option>';
                    
                    select.innerHTML = optionsHTML;
                    if(sensores_dados[oldVal]) select.value = oldVal; else currentSensor = "";

                    if(currentSensor && sensores_dados[currentSensor]) {
                        const sData = sensores_dados[currentSensor].data;
                        
                        // LÓGICA DE SEGURANÇA: Se você está digitando ou salvando, ele não muda os números pra evitar o "bumerangue"
                        if(!isConfigUpdating) {
                            if(document.activeElement.id !== 'remote-router') document.getElementById('remote-router').value = sData.config.router_ip;
                            if(document.activeElement.id !== 'remote-externals') document.getElementById('remote-externals').value = sData.config.external_targets.join(', ');
                        }
                        
                        const diagBox = document.getElementById('diag-box');
                        diagBox.innerText = sData.diagnostics;
                        if (sData.diagnostics.includes("LOOP")) diagBox.className = "status-box warning"; else if (sData.diagnostics.includes("FALHA")) diagBox.className = "status-box error"; else diagBox.className = "status-box ok";

                        const targetsContainer = document.getElementById('targets-container');
                        targetsContainer.innerHTML = '';
                        for (const [target, ms] of Object.entries(sData.current_latencies)) {
                            let statusClass = ms === null ? 'offline' : 'online';
                            let displayMs = ms === null ? 'TIMEOUT' : (ms === 'LOOP_L3' ? 'LOOP' : ms + ' ms');
                            let color = ms === null ? '#f38ba8' : '#a6e3a1';
                            targetsContainer.innerHTML += `<div class="target-card ${statusClass}"><div style="font-size: 0.8em; color: #bac2de;">${target}</div><div style="color: ${color}; font-size: 1.2em; font-weight:bold; margin-top:5px;">${displayMs}</div></div>`;
                        }
                        
                        const globContainer = document.getElementById('globals-container');
                        globContainer.innerHTML = '';
                        for (const [name, ip] of Object.entries(sData.global_targets)) {
                            const msVal = sData.global_latencies[name];
                            let display = msVal === null ? '<span style="color:#f38ba8;">TIMEOUT</span>' : `${msVal} ms`;
                            globContainer.innerHTML += `<div class="global-card"><div class="global-header"><div style="font-weight:bold; color:#cdd6f4;">${name}</div><div class="global-ms">${display}</div></div><div style="font-size:0.7em; color:#6c7086;">IP: ${ip}</div></div>`;
                        }

                        if (sData.latency_history.length > 0) {
                            const newDatasets = []; let colorIndex = 0;
                            const allTargets = Object.keys(sData.current_latencies);
                            allTargets.forEach(target => {
                                const dataPoints = sData.latency_history.map(p => p.latencies[target] !== undefined ? p.latencies[target] : null);
                                const color = colorPalette[colorIndex % colorPalette.length]; colorIndex++;
                                newDatasets.push({ label: target, borderColor: color, backgroundColor: color, borderWidth: 2, data: dataPoints, tension: 0.3, fill: false });
                            });
                            mainChart.data.labels = sData.latency_history.map(p => p.time);
                            mainChart.data.datasets = newDatasets;
                            mainChart.update();
                        }
                    } else { changeSensor(); }
                } catch (e) { console.error(e); }
            }
        </script>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
