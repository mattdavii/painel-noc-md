from flask import Flask, jsonify, request, make_response, render_template_string
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
    # Adicionamos um ID único para o Front-end saber quando apitar o alarme
    novo_id = int(time.time() * 1000)
    eventos_criticos.append({
        "id": novo_id,
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
            registrar_alerta(s_id, f"FALHA CRÍTICA: SENSOR DESCONECTADO (Máquina desligada ou sem internet).", "error")
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

@app.route('/manifest.json')
def serve_manifest():
    manifest = {
        "name": "Network Analyzer PRO", "short_name": "NOC MD", "start_url": "/", "display": "standalone", "orientation": "any",  
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

# --- FRONT-END CENTRAL 2.0 (ENTERPRISE) ---
@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>NOC Enterprise - MD Soluções</title>
        <link rel="manifest" href="/manifest.json">
        
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js"></script>
        
        <style>
            /* VARIÁVEIS DE TEMA (CLARO/ESCURO) */
            :root {
                --bg-main: #1e1e2e; --bg-panel: #313244; --bg-card: #181825;
                --text-main: #cdd6f4; --text-muted: #bac2de; --border: #45475a;
                --accent-blue: #89b4fa; --accent-green: #a6e3a1; --accent-red: #f38ba8;
                --accent-yellow: #f9e2af; --accent-purple: #cba6f7;
            }
            [data-theme="light"] {
                --bg-main: #e2e8f0; --bg-panel: #ffffff; --bg-card: #f8fafc;
                --text-main: #1f2937; --text-muted: #4b5563; --border: #d1d5db;
                --accent-blue: #2563eb; --accent-green: #16a34a; --accent-red: #dc2626;
                --accent-yellow: #d97706; --accent-purple: #7c3aed;
            }

            body { font-family: 'Inter', sans-serif; background-color: var(--bg-main); color: var(--text-main); margin: 0; padding: 0; transition: background 0.3s, color 0.3s; overflow-x: hidden;}
            
            /* NAVBAR SUPERIOR */
            .navbar { background: var(--bg-panel); padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 10px rgba(0,0,0,0.2); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100;}
            .nav-brand { font-size: 1.2em; font-weight: 800; color: var(--accent-blue); letter-spacing: 1px; display: flex; align-items: center; gap: 10px;}
            .nav-controls { display: flex; gap: 15px; align-items: center;}
            .btn-icon { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); padding: 8px 12px; border-radius: 6px; cursor: pointer; transition: 0.2s;}
            .btn-icon:hover { background: var(--border); }
            
            /* ANIMAÇÕES DE LED */
            .led { display: inline-block; width: 12px; height: 12px; border-radius: 50%; box-shadow: 0 0 5px rgba(0,0,0,0.5); }
            .led-green { background-color: var(--accent-green); animation: pulse-green 2s infinite; }
            .led-red { background-color: var(--accent-red); animation: pulse-red 1s infinite; }
            .led-yellow { background-color: var(--accent-yellow); animation: pulse-yellow 1.5s infinite; }
            @keyframes pulse-green { 0% { box-shadow: 0 0 0 0 rgba(166, 227, 161, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(166, 227, 161, 0); } 100% { box-shadow: 0 0 0 0 rgba(166, 227, 161, 0); } }
            @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(243, 139, 168, 0.8); } 70% { box-shadow: 0 0 0 15px rgba(243, 139, 168, 0); } 100% { box-shadow: 0 0 0 0 rgba(243, 139, 168, 0); } }
            @keyframes pulse-yellow { 0% { box-shadow: 0 0 0 0 rgba(249, 226, 175, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(249, 226, 175, 0); } 100% { box-shadow: 0 0 0 0 rgba(249, 226, 175, 0); } }

            /* LAYOUTS PRINCIPAIS */
            .container { max-width: 1600px; margin: 20px auto; padding: 0 20px; }
            #overview-view { display: none; }
            #detail-view { display: none; }
            
            /* VISÃO GERAL (MULTI-SENSOR) */
            .grid-overview { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;}
            .sensor-card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden;}
            .sensor-card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.3); border-color: var(--accent-blue);}
            .card-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px;}
            .card-title { font-size: 1.2em; font-weight: 800; color: var(--text-main); display: flex; align-items: center; gap: 10px;}
            .card-sla { text-align: center; margin: 15px 0; }
            .sla-number { font-size: 2.5em; font-weight: 800; }
            .sla-text { font-size: 0.8em; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px;}
            .card-footer { display: flex; justify-content: space-between; font-size: 0.85em; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 10px;}

            /* LAYOUT DE DETALHES (NOC ANTIGO) */
            .noc-layout { display: grid; grid-template-columns: 3fr 1fr; gap: 20px; align-items: start;}
            .main-panel { background: var(--bg-panel); padding: 25px; border-radius: 12px; border: 1px solid var(--border); }
            .side-panel { background: transparent; display: flex; flex-direction: column; gap: 15px; position: sticky; top: 90px; align-self: start; }
            @media (max-width: 900px) { .noc-layout { grid-template-columns: 1fr; } .side-panel { position: static; } }
            
            /* COMPONENTES INTERNOS */
            .global-alerts-container { background: var(--bg-card); border-left: 4px solid var(--accent-red); padding: 15px; border-radius: 8px; margin-bottom: 20px; max-height: 250px; overflow-y: auto; }
            .alerts-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .alert-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
            .alert-table th, .alert-table td { padding: 10px; border-bottom: 1px solid var(--border); text-align: left; }
            .alert-table th { color: var(--text-muted); position: sticky; top: 0; background: var(--bg-card); }
            
            .status-box { padding: 20px; margin: 20px 0; border-radius: 8px; font-weight: 800; text-align: center; font-size: 1.2em; display: flex; justify-content: center; align-items: center; gap: 10px;}
            .ok { background-color: var(--accent-green); color: #1e1e2e; }
            .error { background-color: var(--accent-red); color: #1e1e2e; }
            .warning { background-color: var(--accent-yellow); color: #1e1e2e; }
            
            .targets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 15px; margin-bottom: 25px;}
            .target-card { background: var(--bg-card); padding: 15px; border-radius: 8px; text-align: center; border: 1px solid var(--border); border-top: 4px solid var(--border);}
            .target-card.online { border-top-color: var(--accent-green); }
            .target-card.offline { border-top-color: var(--accent-red); }
            
            .global-card { background: var(--bg-panel); padding: 15px; border-radius: 8px; border: 1px solid var(--border); border-left: 4px solid var(--accent-blue);}
            .global-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;}
            
            button.action-btn { width: 100%; padding: 12px; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; transition: 0.2s; font-size: 1em; display:flex; justify-content:center; align-items:center; gap: 8px;}
            .btn-scan { background: var(--accent-green); color: #1e1e2e; }
            .btn-scan:hover { filter: brightness(1.1); }
            .btn-logs { background: var(--accent-purple); color: #1e1e2e; margin-bottom: 10px;}
            .btn-danger { background: var(--accent-red); color: #1e1e2e; }
            .btn-save { background: var(--accent-blue); color: #1e1e2e; }

            /* MODAIS E LOGINS */
            #login-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0, 0.85); z-index: 10000; display: flex; justify-content: center; align-items: center; backdrop-filter: blur(10px); }
            .login-box { background: var(--bg-panel); padding: 40px; border-radius: 12px; border: 1px solid var(--border); width: 320px; text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.5);}
            .login-box input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-card); color: var(--text-main); box-sizing: border-box; font-size: 1.1em;}
            
            .input-group { display: flex; flex-direction: column; flex: 1; min-width: 150px; text-align:left;}
            .input-group label { margin-bottom: 5px; font-size: 0.85em; color: var(--text-muted); font-weight: bold;}
            input[type="text"], input[type="date"], select { padding: 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-card); color: var(--text-main); font-family: 'Inter', sans-serif;}

            #scanner-modal { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; backdrop-filter: blur(5px);}
            .modal-content { background: var(--bg-panel); padding: 30px; border-radius: 12px; width: 80%; max-width: 800px; max-height: 80vh; overflow-y: auto; border: 1px solid var(--border);}
        </style>
    </head>
    <body>
        
        <div id="login-overlay">
            <div class="login-box">
                <div style="font-size: 3em; color: var(--accent-blue); margin-bottom: 10px;"><i class="fa-solid fa-shield-halved"></i></div>
                <h2 style="color: var(--text-main); margin-top:0;">Acesso NOC</h2>
                <input type="text" id="login-user" placeholder="Usuário" autocomplete="off">
                <input type="password" id="login-pass" placeholder="Senha" autocomplete="off" onkeypress="if(event.key === 'Enter') doLogin();">
                <button class="action-btn btn-save" onclick="doLogin()"><i class="fa-solid fa-right-to-bracket"></i> Autenticar</button>
                <p id="login-err" style="color: var(--accent-red); font-size: 0.9em; display: none; font-weight: bold; margin-top: 15px;"><i class="fa-solid fa-circle-exclamation"></i> Credenciais Inválidas</p>
            </div>
        </div>

        <div id="scanner-modal">
            <div class="modal-content">
                <span style="float: right; cursor: pointer; color: var(--accent-red); font-size: 1.5em;" onclick="document.getElementById('scanner-modal').style.display='none'"><i class="fa-solid fa-xmark"></i></span>
                <h2 style="color:var(--accent-blue); margin-top:0;" id="modal-title"><i class="fa-solid fa-satellite-dish"></i> Executando Ordem...</h2>
                <div id="scanner-results"><p style="text-align:center; color: var(--text-muted);">Aguardando resposta do hardware...</p></div>
            </div>
        </div>

        <nav class="navbar" id="top-navbar" style="display:none;">
            <div class="nav-brand"><i class="fa-solid fa-network-wired"></i> NOC Enterprise</div>
            <div class="nav-controls">
                <div id="role-badge" style="font-size:0.8em; padding:5px 10px; background:var(--bg-card); border: 1px solid var(--border); border-radius:4px; font-weight:bold; color: var(--accent-green);"></div>
                <button class="btn-icon" id="btn-overview" onclick="showOverview()" style="display:none;" title="Visão Geral"><i class="fa-solid fa-grip"></i> Visão Geral</button>
                <button class="btn-icon" onclick="toggleTheme()" title="Alternar Tema"><i class="fa-solid fa-circle-half-stroke"></i></button>
                <button class="btn-icon" onclick="toggleFullScreen()" title="Tela Cheia"><i class="fa-solid fa-expand"></i></button>
                <button class="btn-icon" onclick="lockScreen()" title="Sair"><i class="fa-solid fa-power-off" style="color: var(--accent-red);"></i></button>
            </div>
        </nav>

        <div class="container" id="main-content">
            
            <div id="overview-view">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
                    <h2 style="margin: 0;"><i class="fa-solid fa-earth-americas"></i> Radar de Sensores Locais</h2>
                    <span style="color: var(--text-muted); font-size: 0.9em;" id="total-sensors-count">0 Sensores Ativos</span>
                </div>
                <div class="grid-overview" id="overview-grid">
                    </div>
            </div>

            <div id="detail-view">
                <div class="noc-layout">
                    <div class="main-panel">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                            <h2 style="margin: 0; color: var(--accent-blue);"><i class="fa-solid fa-server"></i> Sensor: <span id="lbl-sensor-name" style="color:var(--text-main);">...</span></h2>
                            <button class="action-btn" style="width: auto; padding: 8px 15px; background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border);" onclick="showOverview()"><i class="fa-solid fa-arrow-left"></i> Voltar</button>
                        </div>
                        
                        <div class="global-alerts-container">
                            <div class="alerts-header">
                                <h3 style="margin: 0; color: var(--accent-red); font-size:1.1em;"><i class="fa-solid fa-triangle-exclamation"></i> Histórico Crítico</h3>
                                <button id="btn-clear-alerts" class="action-btn" onclick="limparAlertasGlobais()" style="display:none; width:auto; padding: 5px 10px; font-size:0.8em; background: var(--border); color: var(--text-main);"><i class="fa-solid fa-broom"></i> Varrer</button>
                            </div>
                            <table class="alert-table">
                                <thead><tr><th style="width: 25%;">Hora</th><th style="width: 25%;">Máquina</th><th>Incidente</th></tr></thead>
                                <tbody id="global-alerts-body"><tr><td colspan="3" style="text-align:center;">Sem alertas.</td></tr></tbody>
                            </table>
                        </div>

                        <div id="admin-config-panel" style="background: var(--bg-card); padding: 20px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 20px; display:none;">
                            <h4 style="margin: 0 0 15px 0; color:var(--text-main);"><i class="fa-solid fa-sliders"></i> Alterar Configuração Remota</h4>
                            <div style="display: flex; gap: 15px; align-items: flex-end; flex-wrap: wrap;">
                                <div class="input-group">
                                    <label>Gateway / Roteador</label>
                                    <input type="text" id="remote-router">
                                </div>
                                <div class="input-group" style="flex:2;">
                                    <label>Alvos a Monitorar</label>
                                    <input type="text" id="remote-externals">
                                </div>
                                <button id="btn-aplicar" class="action-btn btn-save" onclick="enviarNovaConfig()" style="width: auto; margin-bottom:0;"><i class="fa-solid fa-floppy-disk"></i> Aplicar</button>
                            </div>
                        </div>

                        <div id="diag-box" class="status-box ok"><div class="led led-green"></div> Conectando...</div>
                        <div class="targets-grid" id="targets-container"></div>
                        <div style="background: var(--bg-card); padding: 15px; border-radius: 8px; border: 1px solid var(--border);">
                            <h4 style="color:var(--text-muted); margin-top: 0; margin-bottom: 15px;"><i class="fa-solid fa-chart-line"></i> Latências da Rede Local</h4>
                            <div style="position: relative; height: 300px; width: 100%;"><canvas id="mainChart"></canvas></div>
                        </div>
                    </div>
                    
                    <div class="side-panel" id="sidebar-container">
                        <div id="admin-c2-panel" style="display:none;">
                            <div class="global-card" style="border-left-color: var(--accent-green); margin-bottom: 15px;">
                                <h4 style="margin: 0 0 15px 0; color:var(--text-main); text-align:center;"><i class="fa-solid fa-terminal"></i> Comandos de Rede</h4>
                                <button class="action-btn btn-scan" onclick="enviarComando('SCAN')"><i class="fa-solid fa-magnifying-glass"></i> Escanear Subrede</button>
                            </div>
                            
                            <div class="global-card" style="border-left-color: var(--accent-purple); margin-bottom: 15px;">
                                <h4 style="margin: 0 0 15px 0; color:var(--text-main); text-align:center;"><i class="fa-solid fa-file-pdf"></i> Extração Forense</h4>
                                <label style="font-size:0.8em; color:var(--text-muted); display:block; margin-bottom:5px;">Filtro de Dados:</label>
                                <select id="log-period" onchange="toggleDateInput()" style="width: 100%; margin-bottom: 10px;">
                                    <option value="1">Hoje (Últimas 24h)</option>
                                    <option value="7">Últimos 7 Dias</option>
                                    <option value="15">Últimos 15 Dias</option>
                                    <option value="30">Últimos 30 Dias</option>
                                    <option value="custom">Data Específica...</option>
                                </select>
                                <input type="date" id="log-date" style="display:none; width: 100%; margin-bottom: 10px;">
                                <button class="action-btn btn-logs" onclick="enviarComando('GET_LOGS')"><i class="fa-solid fa-cloud-arrow-down"></i> Baixar PDF</button>
                            </div>
                            
                            <div class="global-card" style="border-left-color: var(--accent-red); margin-bottom: 15px;">
                                <button class="action-btn btn-danger" onclick="confirmarDesinstalacao()"><i class="fa-solid fa-skull-crossbones"></i> Explodir Sensor</button>
                            </div>
                        </div>
                        
                        <div style="text-align:center; color: var(--text-muted); margin-bottom: 10px;"><i class="fa-solid fa-globe"></i> Tráfego Global</div>
                        <div id="globals-container"></div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // --- MOTOR DE ÁUDIO (ALARME DO RADAR) ---
            let audioCtx = null;
            let lastAlertId = null;
            
            function playAlarm() {
                try {
                    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                    if (audioCtx.state === 'suspended') audioCtx.resume();
                    const osc = audioCtx.createOscillator();
                    const gainNode = audioCtx.createGain();
                    osc.type = 'square';
                    osc.frequency.setValueAtTime(800, audioCtx.currentTime); // Frequência de Bip
                    osc.frequency.exponentialRampToValueAtTime(300, audioCtx.currentTime + 0.2); 
                    gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
                    gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
                    osc.connect(gainNode);
                    gainNode.connect(audioCtx.destination);
                    osc.start();
                    osc.stop(audioCtx.currentTime + 0.3);
                } catch(e) { console.log("Áudio bloqueado pelo navegador."); }
            }

            // --- VARIÁVEIS DO SISTEMA ---
            let authUser = ""; let authPass = ""; let userRole = ""; 
            let currentSensor = ""; let mainChart = null; let fetchInterval = null;
            let isConfigUpdating = false; 
            const colorPalette = ['#89b4fa', '#f9e2af', '#cba6f7', '#94e2d5', '#fab387', '#f38ba8'];

            // TEMA E FULLSCREEN
            function toggleTheme() {
                const body = document.body;
                if (body.getAttribute('data-theme') === 'light') body.removeAttribute('data-theme');
                else body.setAttribute('data-theme', 'light');
            }
            function toggleFullScreen() {
                if (!document.fullscreenElement) document.documentElement.requestFullscreen();
                else if (document.exitFullscreen) document.exitFullscreen();
            }

            // --- LOGIN ---
            async function doLogin() {
                const u = document.getElementById('login-user').value;
                const p = document.getElementById('login-pass').value;
                const err = document.getElementById('login-err');
                const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({user:u, pass:p}) });
                
                if(res.status === 200) {
                    const data = await res.json();
                    authUser = u; authPass = p; userRole = data.role;
                    
                    document.getElementById('login-overlay').style.display = 'none';
                    document.getElementById('top-navbar').style.display = 'flex';
                    document.getElementById('overview-view').style.display = 'block';
                    err.style.display = 'none';
                    
                    if(userRole === "admin") {
                        document.getElementById('role-badge').innerHTML = '<i class="fa-solid fa-user-shield"></i> ADMIN'; 
                        document.getElementById('admin-config-panel').style.display = "block"; 
                        document.getElementById('admin-c2-panel').style.display = "block"; 
                        document.getElementById('btn-clear-alerts').style.display = "block";
                    } else {
                        document.getElementById('role-badge').innerHTML = '<i class="fa-solid fa-eye"></i> VIEWER'; 
                        document.getElementById('role-badge').style.color = "var(--accent-yellow)";
                    }
                    
                    // Inicializa o motor de áudio ao clicar no botão de login (Regra do Chrome)
                    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                    
                    fetchMasterData();
                    fetchInterval = setInterval(fetchMasterData, 1500);
                } else { err.style.display = 'block'; }
            }

            function lockScreen() {
                authUser = ""; authPass = ""; userRole = ""; currentSensor = "";
                document.getElementById('login-overlay').style.display = 'flex';
                document.getElementById('top-navbar').style.display = 'none';
                document.getElementById('overview-view').style.display = 'none';
                document.getElementById('detail-view').style.display = 'none';
                document.getElementById('login-pass').value = "";
                if(fetchInterval) clearInterval(fetchInterval);
            }

            function getHeaders() { return { 'Content-Type': 'application/json', 'X-Auth-User': authUser, 'X-Auth-Pass': authPass }; }
            
            // --- NAVEGAÇÃO ---
            function showOverview() {
                currentSensor = "";
                document.getElementById('detail-view').style.display = 'none';
                document.getElementById('overview-view').style.display = 'block';
                document.getElementById('btn-overview').style.display = 'none';
                fetchMasterData(); // Força update imediato
            }

            function selectSensor(id) {
                currentSensor = id;
                document.getElementById('overview-view').style.display = 'none';
                document.getElementById('detail-view').style.display = 'block';
                document.getElementById('btn-overview').style.display = 'block';
                document.getElementById('lbl-sensor-name').innerText = id;
                initChart();
                fetchMasterData();
            }

            function toggleDateInput() {
                const val = document.getElementById('log-period').value;
                document.getElementById('log-date').style.display = val === 'custom' ? 'block' : 'none';
            }

            function initChart() {
                if(mainChart) return;
                const ctx = document.getElementById('mainChart').getContext('2d');
                Chart.defaults.color = '#bac2de';
                mainChart = new Chart(ctx, { type: 'line', data: { labels: [], datasets: [] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(69, 71, 90, 0.3)' } }, x: { grid: { color: 'rgba(69, 71, 90, 0.3)' } } } } });
            }

            // --- FUNÇÕES DE COMANDO (C2) ---
            async function enviarNovaConfig() {
                if(!currentSensor) return;
                isConfigUpdating = true;
                const btn = document.getElementById('btn-aplicar');
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Aplicando...'; btn.disabled = true;
                const r_ip = document.getElementById('remote-router').value;
                const e_tg = document.getElementById('remote-externals').value;
                const res = await fetch('/api/enviar_comando', { method: 'POST', headers: getHeaders(), body: JSON.stringify({sensor_id: currentSensor, comando: "UPDATE_CONFIG", router_ip: r_ip, external_targets: e_tg}) });
                if(res.status === 401) return lockScreen();
                setTimeout(() => { isConfigUpdating = false; btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Aplicar'; btn.disabled = false; }, 4000);
            }
            
            async function enviarComando(cmd) {
                if(!currentSensor) return;
                let payload = {sensor_id: currentSensor, comando: cmd};
                if(cmd === 'GET_LOGS') {
                    const periodVal = document.getElementById('log-period').value;
                    const dateVal = document.getElementById('log-date').value;
                    if(periodVal === 'custom' && !dateVal) return alert("Selecione uma data no calendário!");
                    payload.period = periodVal; payload.date = dateVal;
                }
                const res = await fetch('/api/enviar_comando', { method: 'POST', headers: getHeaders(), body: JSON.stringify(payload) });
                if(res.status === 401) return lockScreen();
                
                if(cmd === 'SCAN') {
                    document.getElementById('modal-title').innerHTML = '<i class="fa-solid fa-satellite-dish"></i> Scanner Remoto';
                    document.getElementById('scanner-modal').style.display = 'flex';
                    document.getElementById('scanner-results').innerHTML = '<p style="text-align:center; color:var(--accent-green);"><i class="fa-solid fa-spinner fa-spin"></i> Varrendo rede do cliente...</p>';
                    let scanInt = setInterval(async () => {
                        const r = await fetch('/api/ler_scan?sensor_id=' + currentSensor, { headers: getHeaders() });
                        const d = await r.json();
                        if(d.status === "pronto") {
                            clearInterval(scanInt);
                            let html = `<table class="alert-table"><thead><tr><th>IP Ativo</th><th>Hostname</th></tr></thead><tbody>`;
                            d.devices.forEach(dev => html += `<tr><td style="color:var(--accent-green); font-weight:bold;">${dev.ip}</td><td>${dev.hostname}</td></tr>`);
                            html += `</tbody></table><p style="text-align:right; font-size:0.8em; color:var(--text-muted);">Total: ${d.devices.length}</p>`;
                            document.getElementById('scanner-results').innerHTML = html;
                        }
                    }, 2000);
                }
                if(cmd === 'GET_LOGS') {
                    document.getElementById('modal-title').innerHTML = '<i class="fa-solid fa-file-pdf"></i> Extração Forense';
                    document.getElementById('scanner-modal').style.display = 'flex';
                    document.getElementById('scanner-results').innerHTML = '<p style="text-align:center; color:var(--accent-purple);"><i class="fa-solid fa-spinner fa-spin"></i> Baixando banco de dados...</p>';
                    let logsInt = setInterval(async () => {
                        const r = await fetch('/api/ler_logs?sensor_id=' + currentSensor, { headers: getHeaders() });
                        const d = await r.json();
                        if(d.status === "pronto") {
                            clearInterval(logsInt); document.getElementById('scanner-modal').style.display = 'none'; gerarPDF(d.logs);
                        }
                    }, 2000);
                }
            }

            async function gerarPDF(logsData) {
                if(logsData.length === 0) return alert("O banco de dados está limpo neste período.");
                const { jsPDF } = window.jspdf; const doc = new jsPDF('landscape');
                doc.setFillColor(49, 50, 68); doc.rect(0, 0, doc.internal.pageSize.width, 25, 'F');
                doc.setTextColor(255, 255, 255); doc.setFontSize(16); doc.setFont("helvetica", "bold");
                doc.text(`NOC Enterprise - Relatorio Forense [${currentSensor}]`, 14, 16);
                
                const tableData = logsData.map(log => [log.time, log.level.toUpperCase(), log.message.replace(/\[Status no momento: (.*?)\]/g, '\\n>> Latências: $1')]);
                doc.autoTable({
                    startY: 35, head: [['Data / Hora', 'Nível', 'Descrição do Evento']], body: tableData, theme: 'grid',
                    styles: { fontSize: 9, cellPadding: 3 }, headStyles: { fillColor: [49, 50, 68] },
                    willDrawCell: function (data) {
                        if (data.section === 'body' && data.column.index === 1) {
                            if (data.cell.raw === 'ERROR') doc.setTextColor(220, 53, 69);
                            else if (data.cell.raw === 'WARNING') doc.setTextColor(253, 126, 20);
                            else doc.setTextColor(13, 110, 253);
                        }
                    }
                });
                doc.save(`NOC_${currentSensor}_${new Date().toISOString().split('T')[0]}.pdf`);
            }

            function confirmarDesinstalacao() { if(confirm("Deseja explodir o sensor remotamente?")) { enviarComando('UNINSTALL'); alert("Ordem enviada."); } }
            async function limparAlertasGlobais() { await fetch('/api/limpar_alertas', { method: 'POST', headers: getHeaders() }); }

            // --- MOTOR PRINCIPAL ---
            async function fetchMasterData() {
                try {
                    const res = await fetch('/api/sensores', { headers: getHeaders() });
                    if(res.status === 401) return lockScreen();
                    
                    const masterData = await res.json();
                    const sensores_dados = masterData.sensores || {};
                    const alertas_dados = masterData.alertas || [];
                    
                    document.getElementById('total-sensors-count').innerText = `${Object.keys(sensores_dados).length} Usinas Operantes`;

                    // LÓGICA DO ALARME SONORO
                    if (alertas_dados.length > 0) {
                        const alertRecente = alertas_dados[0];
                        if (alertRecente.level === 'error' && alertRecente.id !== lastAlertId) {
                            lastAlertId = alertRecente.id;
                            playAlarm(); // Bip do Radar!
                        }
                    }

                    // ATUALIZA TABELA DE ALERTAS
                    const alertasTbody = document.getElementById('global-alerts-body');
                    if(alertas_dados.length === 0) { alertasTbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--accent-green);"><i class="fa-solid fa-check-circle"></i> Rede Global Estável.</td></tr>';
                    } else {
                        alertasTbody.innerHTML = '';
                        alertas_dados.forEach(alerta => {
                            const isErr = alerta.level === 'error';
                            const icon = isErr ? '<i class="fa-solid fa-circle-xmark"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';
                            const color = isErr ? 'var(--accent-red)' : 'var(--accent-yellow)';
                            alertasTbody.innerHTML += `<tr><td>${alerta.time}</td><td><span class="sensor-badge">${alerta.sensor_id}</span></td><td style="color:${color}; font-weight:bold;">${icon} ${alerta.msg}</td></tr>`;
                        });
                    }

                    // --- MODO VISÃO GERAL (CARDS) ---
                    if (!currentSensor) {
                        const grid = document.getElementById('overview-grid');
                        grid.innerHTML = '';
                        if (Object.keys(sensores_dados).length === 0) {
                            grid.innerHTML = '<p style="color:var(--text-muted); grid-column: 1 / -1; text-align:center; margin-top: 50px;"><i class="fa-solid fa-satellite fa-3x" style="display:block; margin-bottom:15px; opacity:0.5;"></i>Nenhum hardware transmitindo sinal.</p>';
                        } else {
                            for (const [s_id, s_info] of Object.entries(sensores_dados)) {
                                const latencies = s_info.data.current_latencies;
                                const total = Object.keys(latencies).length;
                                let offline = 0;
                                for (let ms of Object.values(latencies)) { if (ms === null || ms === "LOOP_L3") offline++; }
                                
                                let sla = 100;
                                if (total > 0) sla = Math.round(((total - offline) / total) * 100);
                                
                                let ledClass = "led-green"; let borderCard = "var(--border)"; let statusText = "Operacional";
                                if (sla < 100 && sla > 0) { ledClass = "led-yellow"; borderCard = "var(--accent-yellow)"; statusText = "Instabilidade"; }
                                else if (sla === 0 || s_info.data.diagnostics.includes("LOOP") || s_info.data.diagnostics.includes("FALHA")) { ledClass = "led-red"; borderCard = "var(--accent-red)"; statusText = "Queda Crítica"; }

                                grid.innerHTML += `
                                    <div class="sensor-card" style="border-left: 4px solid ${borderCard};" onclick="selectSensor('${s_id}')">
                                        <div class="card-header"><div class="card-title"><div class="led ${ledClass}"></div> ${s_id}</div></div>
                                        <div class="card-sla"><div class="sla-number" style="color:${borderCard};">${sla}%</div><div class="sla-text">Saúde da Rede (SLA)</div></div>
                                        <div class="card-footer"><span><i class="fa-solid fa-network-wired"></i> ${total} Alvos</span><span style="color:${borderCard}; font-weight:bold;">${statusText}</span></div>
                                    </div>
                                `;
                            }
                        }
                    } 
                    // --- MODO DETALHES (SENSOR ESPECÍFICO) ---
                    else if (sensores_dados[currentSensor]) {
                        const sData = sensores_dados[currentSensor].data;
                        
                        if(!isConfigUpdating) {
                            if(document.activeElement.id !== 'remote-router') document.getElementById('remote-router').value = sData.config.router_ip;
                            if(document.activeElement.id !== 'remote-externals') document.getElementById('remote-externals').value = sData.config.external_targets.join(', ');
                        }
                        
                        const diagBox = document.getElementById('diag-box');
                        
                        if (sData.diagnostics.includes("LOOP")) diagBox.innerHTML = `<div class="led led-red"></div> <i class="fa-solid fa-rotate"></i> ${sData.diagnostics}`; 
                        else if (sData.diagnostics.includes("FALHA")) diagBox.innerHTML = `<div class="led led-red"></div> <i class="fa-solid fa-plug-circle-xmark"></i> ${sData.diagnostics}`; 
                        else if (sData.diagnostics.includes("INSTABILIDADE") || sData.diagnostics.includes("INTERNET")) diagBox.innerHTML = `<div class="led led-yellow"></div> <i class="fa-solid fa-cloud-bolt"></i> ${sData.diagnostics}`; 
                        else diagBox.innerHTML = `<div class="led led-green"></div> <i class="fa-solid fa-check-double"></i> ${sData.diagnostics}`;

                        // Ajuste de classes de cor para o DiagBox
                        if (sData.diagnostics.includes("LOOP") || sData.diagnostics.includes("FALHA")) diagBox.className = "status-box error";
                        else if (sData.diagnostics.includes("INSTABILIDADE") || sData.diagnostics.includes("INTERNET")) diagBox.className = "status-box warning";
                        else diagBox.className = "status-box ok";

                        const targetsContainer = document.getElementById('targets-container');
                        targetsContainer.innerHTML = '';
                        for (const [target, ms] of Object.entries(sData.current_latencies)) {
                            let statusClass = ms === null ? 'offline' : 'online';
                            let displayMs = ms === null ? 'TIMEOUT' : (ms === 'LOOP_L3' ? 'LOOP / TTL' : ms + ' ms');
                            let color = ms === null ? 'var(--accent-red)' : 'var(--accent-green)';
                            let icon = ms === null ? '<i class="fa-solid fa-xmark"></i>' : '<i class="fa-solid fa-check"></i>';
                            targetsContainer.innerHTML += `<div class="target-card ${statusClass}"><div style="font-size: 0.8em; color: var(--text-muted);">${target}</div><div style="color: ${color}; font-size: 1.1em; font-weight:bold; margin-top:8px;">${icon} ${displayMs}</div></div>`;
                        }
                        
                        const globContainer = document.getElementById('globals-container');
                        globContainer.innerHTML = '';
                        for (const [name, ip] of Object.entries(sData.global_targets)) {
                            const msVal = sData.global_latencies[name];
                            let display = msVal === null ? '<span style="color:var(--accent-red);"><i class="fa-solid fa-bolt-lightning"></i> TIMEOUT</span>' : `${msVal} ms`;
                            globContainer.innerHTML += `<div class="global-card"><div class="global-header"><div style="font-weight:bold; color:var(--text-main);">${name}</div><div class="global-ms">${display}</div></div><div style="font-size:0.7em; color:var(--text-muted);"><i class="fa-solid fa-location-crosshairs"></i> ${ip}</div></div>`;
                        }

                        if (sData.latency_history.length > 0) {
                            const newDatasets = []; let colorIndex = 0;
                            const allTargets = Object.keys(sData.current_latencies);
                            allTargets.forEach(target => {
                                const dataPoints = sData.latency_history.map(p => p.latencies[target] !== undefined ? p.latencies[target] : null);
                                const color = colorPalette[colorIndex % colorPalette.length]; colorIndex++;
                                newDatasets.push({ label: target, borderColor: color, backgroundColor: color, borderWidth: 2, data: dataPoints, tension: 0.3, fill: false, pointRadius: 2 });
                            });
                            mainChart.data.labels = sData.latency_history.map(p => p.time);
                            mainChart.data.datasets = newDatasets;
                            mainChart.update();
                        }
                    } else { showOverview(); } // Se o sensor morrer enquanto você estiver olhando pra ele, volta pro radar
                } catch (e) {}
            }
        </script>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
