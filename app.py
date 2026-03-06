from flask import Flask, jsonify, render_template_string, request
from datetime import datetime
import time

app = Flask(__name__)

# --- BANCO DE DADOS EM MEMÓRIA DA NUVEM ---
sensores_conectados = {}
comandos_pendentes = {} # Ex: {"USINA-01": "SCAN"}
resultados_scan = {}    # Ex: {"USINA-01": [{"ip": "192...", "hostname": "PC"}]}

# 1. Rota que o .exe chama a cada 1 segundo para mandar os dados
@app.route('/api/receber_dados', methods=['POST'])
def receber_dados():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    
    if sensor_id:
        sensores_conectados[sensor_id] = {
            "last_ping": time.time(),
            "data": payload
        }
        
    # Verifica se o Painel (Você) mandou alguma ordem para esse sensor
    comando = comandos_pendentes.pop(sensor_id, None)
    
    return jsonify({"status": "sucesso", "comando": comando})

# 2. Rota que o .exe chama quando termina de escanear a rede
@app.route('/api/receber_scan', methods=['POST'])
def receber_scan():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    resultados_scan[sensor_id] = payload.get("devices", [])
    return jsonify({"status": "recebido"})

# 3. Rotas para o Painel Web (Front-end)
@app.route('/api/sensores')
def get_sensores():
    agora = time.time()
    # Remove da lista sensores que não mandam dados há 15 segundos
    ativos = {k: v for k, v in sensores_conectados.items() if agora - v['last_ping'] < 15}
    sensores_conectados.clear()
    sensores_conectados.update(ativos)
    return jsonify(sensores_conectados)

@app.route('/api/enviar_comando', methods=['POST'])
def enviar_comando():
    dados = request.json
    sensor_id = dados.get("sensor_id")
    comando = dados.get("comando")
    comandos_pendentes[sensor_id] = comando
    
    if comando == "SCAN":
        resultados_scan.pop(sensor_id, None) # Limpa scan antigo
        
    return jsonify({"status": "enviado"})

@app.route('/api/ler_scan')
def ler_scan():
    sensor_id = request.args.get("sensor_id")
    if sensor_id in resultados_scan:
        return jsonify({"status": "pronto", "devices": resultados_scan[sensor_id]})
    return jsonify({"status": "aguardando"})

# --- FRONT-END ---
@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Analyzer PRO - Central</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }
            .noc-layout { display: grid; grid-template-columns: 3fr 1fr; gap: 20px; max-width: 1500px; margin: 0 auto; align-items: start;}
            .main-panel { background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            .side-panel { background: #1e1e2e; display: flex; flex-direction: column; gap: 15px; position: sticky; top: 15px; align-self: start; }
            @media (max-width: 900px) { .noc-layout { grid-template-columns: 1fr; } .side-panel { position: static; } }
            
            h1 { color: #89b4fa; text-align: center; margin-top: 0; }
            .brand-header { text-align: center; font-size: 0.75em; color: #6c7086; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 5px; font-weight: bold; }
            
            .selector-container { background: #181825; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; border: 2px solid #a6e3a1;}
            select { padding: 10px; font-size: 1.1em; border-radius: 4px; background: #1e1e2e; color: #a6e3a1; font-weight: bold; border: 1px solid #45475a; min-width: 300px; cursor: pointer;}
            
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
            .global-ms.timeout { color: #f38ba8; }
            
            button { padding: 10px 15px; font-weight: bold; border: none; border-radius: 4px; cursor: pointer; width: 100%; margin-bottom: 10px; transition: 0.2s;}
            .btn-scan { background: #a6e3a1; color: #1e1e2e; }
            .btn-scan:hover { background: #94e2d5; }
            .btn-danger { background: #f38ba8; color: #1e1e2e; }
            .btn-danger:hover { background: #eba0ac; }
            
            #scanner-modal { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center;}
            .modal-content { background: #313244; padding: 20px; border-radius: 8px; width: 80%; max-width: 800px; max-height: 80vh; overflow-y: auto;}
            .close-btn { float: right; cursor: pointer; color: #f38ba8; font-weight: bold; font-size: 1.2em;}
            table { width: 100%; border-collapse: collapse; margin-top: 15px; } th, td { padding: 10px; border-bottom: 1px solid #45475a; text-align: left; } th { color: #bac2de; }
        </style>
    </head>
    <body>
        <div id="scanner-modal">
            <div class="modal-content">
                <span class="close-btn" onclick="document.getElementById('scanner-modal').style.display='none'">✖ Fechar</span>
                <h2 style="color:#a6e3a1; margin-top:0;">🔍 Resultados do Scanner Remoto</h2>
                <div id="scanner-results"><p style="text-align:center;">Aguardando o Sensor executar a varredura e enviar os dados... (Isso pode levar 15 segundos)</p></div>
            </div>
        </div>

        <div class="noc-layout">
            <div class="main-panel">
                <div class="brand-header">MD Soluções Tecnológicas</div>
                <h1>🌐 Network Analyzer PRO - Central</h1>
                
                <div class="selector-container">
                    <label style="color: #bac2de; font-weight:bold; margin-right:10px;">Monitorar Sensor:</label>
                    <select id="sensor-select" onchange="changeSensor()">
                        <option value="">Aguardando conexão de sensores...</option>
                    </select>
                </div>

                <div id="offline-alert" class="offline-msg">⚠️ Nenhum Sensor Selecionado ou Máquina Offline.</div>

                <div id="dashboard-content" style="display:none;">
                    <div id="diag-box" class="status-box ok">Conectando...</div>
                    <div class="targets-grid" id="targets-container"></div>
                    <h4 style="color:#bac2de; margin-bottom: 5px;">Latências da Rede Local do Sensor</h4>
                    <div class="chart-container"><canvas id="mainChart"></canvas></div>
                </div>
            </div>
            
            <div class="side-panel" id="sidebar-container" style="display:none;">
                <div class="global-card" style="border-left-color: #f9e2af;">
                    <h4 style="margin: 0 0 10px 0; color:#cdd6f4; text-align:center;">Comandos Remotos</h4>
                    <button class="btn-scan" onclick="enviarComando('SCAN')">🔍 Escanear Rede do Cliente</button>
                    <button class="btn-danger" onclick="confirmarDesinstalacao()">🗑️ Auto-Destruir Sensor</button>
                </div>
                
                <h3 style="color: #bac2de; margin-bottom: 0; text-align:center;">🌐 Tráfego Global</h3>
                <p style="font-size: 0.8em; text-align: center; color: #6c7086; margin-top:0;">Visão a partir do cliente</p>
                <div id="globals-container"></div>
            </div>
        </div>

        <script>
            let currentSensor = ""; let mainChart = null; let scanInterval = null;
            const colorPalette = ['#89b4fa', '#f9e2af', '#cba6f7', '#94e2d5', '#fab387', '#f38ba8'];

            function initChart() {
                const ctx = document.getElementById('mainChart').getContext('2d');
                mainChart = new Chart(ctx, { type: 'line', data: { labels: [], datasets: [] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 }, scales: { y: { beginAtZero: true, grid: { color: '#45475a' } }, x: { grid: { color: '#45475a' } } }, plugins: { legend: { labels: { color: '#cdd6f4' } } } } });
            }

            function changeSensor() {
                currentSensor = document.getElementById('sensor-select').value;
                if(currentSensor) {
                    document.getElementById('dashboard-content').style.display = 'block';
                    document.getElementById('sidebar-container').style.display = 'flex';
                    document.getElementById('offline-alert').style.display = 'none';
                } else {
                    document.getElementById('dashboard-content').style.display = 'none';
                    document.getElementById('sidebar-container').style.display = 'none';
                    document.getElementById('offline-alert').style.display = 'block';
                }
            }
            
            async function enviarComando(cmd) {
                if(!currentSensor) return;
                await fetch('/api/enviar_comando', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({sensor_id: currentSensor, comando: cmd}) });
                
                if(cmd === 'SCAN') {
                    document.getElementById('scanner-modal').style.display = 'flex';
                    document.getElementById('scanner-results').innerHTML = '<p style="text-align:center; color:#f9e2af;">Ordem enviada! Aguardando o Sensor processar a varredura local...</p>';
                    if(scanInterval) clearInterval(scanInterval);
                    scanInterval = setInterval(verificarScan, 2000);
                }
            }

            function confirmarDesinstalacao() {
                if(confirm("⚠️ ATENÇÃO EXTREMA!\\n\\nIsso fará o executável se APAGAR PERMANENTEMENTE da máquina do cliente.\\nVocê perderá o acesso instantaneamente.\\n\\nDeseja realmente explodir o sensor remotamente?")) {
                    enviarComando('UNINSTALL');
                    alert("Ordem de Auto-destruição enviada. O painel perderá o contato em 5 segundos.");
                }
            }

            async function verificarScan() {
                const res = await fetch('/api/ler_scan?sensor_id=' + currentSensor);
                const data = await res.json();
                if(data.status === "pronto") {
                    clearInterval(scanInterval);
                    let html = `<table><thead><tr><th>IP Encontrado</th><th>Hostname</th></tr></thead><tbody>`;
                    data.devices.forEach(d => html += `<tr><td style="color:#a6e3a1; font-weight:bold;">${d.ip}</td><td>${d.hostname}</td></tr>`);
                    html += `</tbody></table><p style="text-align:right; font-size:0.8em; color:#a6adc8;">Total: ${data.devices.length} dispositivos.</p>`;
                    document.getElementById('scanner-results').innerHTML = html;
                }
            }

            async function fetchMasterData() {
                try {
                    const res = await fetch('/api/sensores');
                    const data = await res.json();
                    
                    const select = document.getElementById('sensor-select');
                    const oldVal = select.value;
                    let optionsHTML = '<option value="">-- Selecione uma Máquina --</option>';
                    for(const s_id in data) optionsHTML += `<option value="${s_id}">🟢 Sensor Online: ${s_id}</option>`;
                    if(Object.keys(data).length === 0) optionsHTML = '<option value="">🔴 Nenhum sensor online na rede</option>';
                    
                    select.innerHTML = optionsHTML;
                    if(data[oldVal]) select.value = oldVal; else currentSensor = "";

                    if(currentSensor && data[currentSensor]) {
                        const sData = data[currentSensor].data;
                        
                        const diagBox = document.getElementById('diag-box');
                        diagBox.innerText = sData.diagnostics;
                        if (sData.diagnostics.includes("LOOP")) diagBox.className = "status-box warning";
                        else if (sData.diagnostics.includes("FALHA")) diagBox.className = "status-box error";
                        else diagBox.className = "status-box ok";

                        const targetsContainer = document.getElementById('targets-container');
                        targetsContainer.innerHTML = '';
                        for (const [target, ms] of Object.entries(sData.current_latencies)) {
                            let statusClass = ms === null ? 'offline' : 'online';
                            let displayMs = ms === null ? 'TIMEOUT' : (ms === 'LOOP_L3' ? 'LOOP' : ms + ' ms');
                            let color = ms === null ? '#f38ba8' : '#a6e3a1';
                            targetsContainer.innerHTML += `<div class="target-card ${statusClass}"><div style="font-size: 0.8em; color: #bac2de;">${target}</div><div style="color: ${color}; font-size: 1.2em; font-weight:bold; margin-top:5px;">${displayMs}</div></div>`;
                        }
                        
                        // Atualiza Globais na Lateral
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

            initChart();
            setInterval(fetchMasterData, 1000);
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
