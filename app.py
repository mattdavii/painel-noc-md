from flask import Flask, jsonify, render_template_string, request
from datetime import datetime
import time

app = Flask(__name__)

# Banco de Dados em Memória (Ideal para o Render Free, super rápido)
sensores_conectados = {}

@app.route('/api/receber_dados', methods=['POST'])
def receber_dados():
    payload = request.json
    sensor_id = payload.get("sensor_id")
    if sensor_id:
        sensores_conectados[sensor_id] = {
            "last_ping": time.time(),
            "data": payload
        }
    return jsonify({"status": "sucesso"})

@app.route('/api/sensores')
def get_sensores():
    # Remove sensores que não mandam dados há mais de 30 segundos (Ficaram Offline)
    agora = time.time()
    ativos = {k: v for k, v in sensores_conectados.items() if agora - v['last_ping'] < 30}
    sensores_conectados.clear()
    sensores_conectados.update(ativos)
    return jsonify(sensores_conectados)

@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NOC Central - MD Soluções</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }
            .container { max-width: 1200px; margin: 0 auto; background: #313244; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            h1 { color: #89b4fa; text-align: center; margin-top: 0; }
            .selector-container { background: #181825; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; border: 2px solid #a6e3a1;}
            select { padding: 10px; font-size: 1.1em; border-radius: 4px; background: #1e1e2e; color: #a6e3a1; font-weight: bold; border: 1px solid #45475a; min-width: 300px; cursor: pointer;}
            .status-box { padding: 15px; margin: 15px 0; border-radius: 5px; font-weight: bold; text-align: center; font-size: 1.1em;}
            .ok { background-color: #a6e3a1; color: #1e1e2e; }
            .error { background-color: #f38ba8; color: #1e1e2e; }
            .warning { background-color: #f9e2af; color: #1e1e2e; }
            .targets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin-bottom: 20px;}
            .target-card { background: #181825; padding: 10px; border-radius: 6px; text-align: center; border-left: 4px solid #45475a;}
            .chart-container { position: relative; height: 300px; width: 100%; margin-bottom: 20px; background: #181825; padding: 15px; border-radius: 8px; box-sizing: border-box;}
            .offline-msg { text-align: center; color: #f38ba8; font-size: 1.2em; margin: 50px 0; display: none;}
        </style>
    </head>
    <body>
        <div class="container">
            <div style="text-align: center; font-size: 0.8em; color: #6c7086; letter-spacing: 2px; font-weight:bold;">MD SOLUÇÕES TECNOLÓGICAS</div>
            <h1>🌐 NOC Central (Painel Mestre)</h1>
            
            <div class="selector-container">
                <label style="color: #bac2de; font-weight:bold; margin-right:10px;">Monitorar Sensor:</label>
                <select id="sensor-select" onchange="changeSensor()">
                    <option value="">Aguardando sensores conectarem...</option>
                </select>
            </div>

            <div id="offline-alert" class="offline-msg">⚠️ Nenhum Sensor Selecionado ou Offline.</div>

            <div id="dashboard-content" style="display:none;">
                <div id="diag-box" class="status-box ok">Conectando...</div>
                <div class="targets-grid" id="targets-container"></div>
                <div class="chart-container"><canvas id="mainChart"></canvas></div>
            </div>
        </div>

        <script>
            let currentSensor = "";
            let mainChart = null;
            const colorPalette = ['#89b4fa', '#f9e2af', '#cba6f7', '#94e2d5', '#fab387', '#f38ba8'];

            function initChart() {
                const ctx = document.getElementById('mainChart').getContext('2d');
                mainChart = new Chart(ctx, { type: 'line', data: { labels: [], datasets: [] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 }, scales: { y: { beginAtZero: true, grid: { color: '#45475a' } }, x: { grid: { color: '#45475a' } } }, plugins: { legend: { labels: { color: '#cdd6f4' } } } } });
            }

            function changeSensor() {
                currentSensor = document.getElementById('sensor-select').value;
                if(currentSensor) {
                    document.getElementById('dashboard-content').style.display = 'block';
                    document.getElementById('offline-alert').style.display = 'none';
                } else {
                    document.getElementById('dashboard-content').style.display = 'none';
                    document.getElementById('offline-alert').style.display = 'block';
                }
            }

            async function fetchMasterData() {
                try {
                    const res = await fetch('/api/sensores');
                    const data = await res.json();
                    
                    // Atualiza a lista de opções (Dropdown)
                    const select = document.getElementById('sensor-select');
                    const oldVal = select.value;
                    let optionsHTML = '<option value="">-- Selecione uma Usina/Máquina --</option>';
                    for(const s_id in data) {
                        optionsHTML += `<option value="${s_id}">🟢 Sensor: ${s_id}</option>`;
                    }
                    if(Object.keys(data).length === 0) optionsHTML = '<option value="">🔴 Nenhum sensor online na rede</option>';
                    
                    select.innerHTML = optionsHTML;
                    if(data[oldVal]) select.value = oldVal;
                    else currentSensor = ""; // Caiu

                    // Desenha o Dashboard do sensor selecionado
                    if(currentSensor && data[currentSensor]) {
                        const sData = data[currentSensor].data;
                        
                        const diagBox = document.getElementById('diag-box');
                        diagBox.innerText = sData.diagnostics;
                        if (sData.diagnostics.includes("LOOP") || sData.diagnostics.includes("ALERTA")) diagBox.className = "status-box warning";
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
                    } else {
                        changeSensor();
                    }
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