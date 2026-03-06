from flask import Flask, jsonify, render_template_string, request, make_response
from datetime import datetime, timedelta
import time

app = Flask(__name__)

# --- SISTEMA DE LOGINS (RBAC) ---
USUARIOS = {
    "admin": {"senha": "100110Md.", "role": "admin"},
    "cliente": {"senha": "cliente123", "role": "viewer"}
}

def authenticate():
    return make_response('Acesso negado. Insira as credenciais da MD Solucoes.', 401, {'WWW-Authenticate': 'Basic realm="Network Analyzer PRO"'})

@app.before_request
def require_auth():
    if request.path in ['/api/receber_dados', '/api/receber_scan', '/manifest.json', '/sw.js']:
        return
    
    auth = request.authorization
    if not auth or auth.username not in USUARIOS or USUARIOS[auth.username]["senha"] != auth.password:
        return authenticate()
    
    request.user_role = USUARIOS[auth.username]["role"]

# --- BANCO DE DADOS EM MEMÓRIA ---
sensores_conectados = {}
comandos_pendentes = {} 
resultados_scan = {}
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
        sensores_conectados[sensor_id] = {
            "last_ping": time.time(),
            "data": payload
        }
        
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
    
    return jsonify({
        "sensores": sensores_conectados,
        "alertas": list(reversed(eventos_criticos)) 
    })

@app.route('/api/limpar_alertas', methods=['POST'])
def limpar_alertas():
    if request.user_role == 'admin':
        eventos_criticos.clear()
    return jsonify({"status": "limpo"})

@app.route('/api/enviar_comando', methods=['POST'])
def enviar_comando():
    if request.user_role != 'admin':
        return jsonify({"status": "erro", "msg": "Sem permissão"}), 403
        
    dados = request.json
    sensor_id = dados.get("sensor_id")
    comando = dados.get("comando")
    
    pacote = {"comando": comando}
    if comando == "UPDATE_CONFIG":
        pacote["router_ip"] = dados.get("router_ip")
        pacote["external_targets"] = dados.get("external_targets")
        
    comandos_pendentes[sensor_id] = pacote
    if comando == "SCAN":
        resultados_scan.pop(sensor_id, None) 
        
    return jsonify({"status": "enviado"})

@app.route('/api/ler_scan')
def ler_scan():
    sensor_id = request.args.get("sensor_id")
    if sensor_id in resultados_scan:
        return jsonify({"status": "pronto", "devices": resultados_scan[sensor_id]})
    return jsonify({"status": "aguardando"})

# --- ROTAS DO PWA ---
@app.route('/manifest.json')
def serve_manifest():
    manifest = {
        "name": "Network Analyzer PRO - Central",
        "short_name": "NetAnalyzer",
        "start_url": "/",
        "display": "standalone",
        "orientation": "any",  
        "background_color": "#1e1e2e",
        "theme_color": "#89b4fa",
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
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Network Analyzer PRO - Central</title>
        
        <link rel="manifest" href="/manifest.json">
        <meta name="theme-color" content="#89b4fa">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
        <link rel="apple-touch-icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iIzFlMWUyZSIvPjxjaXJjbGUgY3g9IjUwIiBjeT0iNTAiIHI9IjQwIiBmaWxsPSJub25lIiBzdHJva2U9IiM4OWI0ZmEiIHN0cm9rZS13aWR0aD0iOCIvPjxwb2x5bGluZSBwb2ludHM9IjMwLDUwIDQ1LDY1IDcwLDM1IiBmaWxsPSJub25lIiBzdHJva2U9IiNhNmUzYTEiIHN0cm9rZS13aWR0aD0iOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PC9zdmc+">
        
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }}
            .noc-layout {{ display: grid; grid-template-columns: 3fr 1fr; gap: 20px; max-width: 1500px; margin: 0 auto; align-items: start;}}
            .main-panel {{ background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
            .side-panel {{ background: #1e1e2e; display: flex; flex-direction: column; gap: 15px; position: sticky; top: 15px; align-self: start; }}
            
            /* CSS Responsivo Otimizado */
            @media (max-width: 900px) {{ 
                .noc-layout {{ grid-template-columns: 1fr; }} 
                .side-panel {{ position: static; }} 
            }}
            
            h1 {{ color: #89b4fa; text-align: center; margin-top: 0; }}
            .brand-header {{ text-align: center; font-size: 0.75em; color: #6c7086; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 5px; font-weight: bold; }}
            
            .global-alerts-container {{ background: #181825; border-left: 4px solid #f38ba8; padding: 15px; border-radius: 8px; margin-bottom: 20px; max-height: 250px; overflow-y: auto; }}
            .alerts-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
            .btn-clear-alerts {{ background: #45475a; color: #cdd6f4; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 0.8em; }}
            .btn-clear-alerts:hover {{ background: #585b70; }}
            .alert-table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
            .alert-table th, .alert-table td {{ padding: 8px; border-bottom: 1px solid #313244; text-align: left; }}
            .alert-table th {{ color: #bac2de; position: sticky; top: 0; background: #181825; }}
            .alert-error {{ color: #f38ba8; font
