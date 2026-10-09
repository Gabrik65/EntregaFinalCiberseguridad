"""Genera un panel local sin CDN, servidor ni ejecución de datos externos."""

import json
from pathlib import Path


# La plantilla es autónoma: Python incorpora JSON validado y JavaScript lo presenta.
TEMPLATE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Observatorio de seguridad</title>
<style>
:root{font-family:system-ui,sans-serif;color:#19322d;background:#f4f5ef;--green:#146b57;--muted:#62746d}
*{box-sizing:border-box}body{margin:0}header{background:#102e29;color:#fff;padding:46px max(5vw,20px)}
header p{color:#bbd2c8;max-width:780px;line-height:1.6}h1{font-size:clamp(28px,4vw,48px);margin:12px 0;letter-spacing:-1.5px}
.eyebrow{font-size:12px;letter-spacing:2px;text-transform:uppercase}main{max-width:1440px;margin:auto;padding:30px 5vw}
h2{font-size:23px;margin:0 0 16px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,.panel{background:white;border:1px solid #dae2d8;border-radius:14px;padding:22px}.card strong{display:block;font-size:32px;margin:8px 0}.muted,small{color:var(--muted)}
.panel{margin-top:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:25px}.barrow{display:grid;grid-template-columns:90px 1fr 40px;align-items:center;gap:12px;margin:12px 0}.track{height:15px;background:#e6ebe5;border-radius:10px;overflow:hidden}.bar{height:100%;background:var(--green)}
.category-chart .barrow{grid-template-columns:210px 1fr 40px}
label{font-weight:600;font-size:14px}select,input,button{font:inherit;border:1px solid #bdcec3;border-radius:7px;padding:9px;background:white;color:#19322d}button{cursor:pointer}button:disabled{opacity:.4}.filters{display:flex;flex-wrap:wrap;gap:20px;align-items:end}.filters label{display:grid;gap:8px}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:13px 10px;border-bottom:1px solid #e6ece5;vertical-align:top}th{color:#4a6258;white-space:nowrap}.badge{display:inline-block;padding:4px 8px;border-radius:5px;background:#e2f1e7;font-size:12px}.bad{background:#ffeadb;color:#814b22}.neutral{background:#edf0f3;color:#475564}.notes{line-height:1.65}.pager{display:flex;gap:15px;align-items:center;justify-content:flex-end;margin-top:16px}code{font-size:12px;overflow-wrap:anywhere}.empty{padding:24px;color:#62746d}footer{padding:26px 5vw;color:#62746d;font-size:13px}
@media(max-width:750px){.cards{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}main{padding:20px}header{padding:30px 20px}.card{padding:15px}.filters label{width:100%}}
</style></head><body><header><div class="eyebrow">Proyecto semestral · resultados observados</div>
<h1>Observatorio de seguridad</h1><p>Una vista reproducible del código y sus dependencias. Las alertas señalan elementos para revisar; los estados muestran qué se analizó realmente.</p></header>
<main><section class="cards" id="cards"></section>
<section class="panel"><h2>Cobertura de la muestra</h2><p class="muted" id="coverage-note"></p><div id="coverage"></div></section>
<section class="panel grid"><div><h2>Niveles de alertas de CodeQL</h2><div id="code-chart"></div></div><div><h2>Severidad de dependencias</h2><div id="dep-chart"></div></div></section>
<section class="panel"><h2>Comparación por categoría</h2><p class="muted">Conteos observados; cada fila indica cuántos repositorios completaron la herramienta correspondiente.</p><div class="grid"><div class="category-chart"><h3>Alertas de código</h3><div id="category-code"></div></div><div class="category-chart"><h3>Coincidencias en dependencias</h3><div id="category-dependency"></div></div></div></section>
<section class="panel"><h2>Explorar resultados</h2><div class="filters"><label>Categoría<select id="category"><option value="">Todas</option></select></label><label>Repositorio<select id="repository"><option value="">Todos</option></select></label><label>Herramienta<select id="tool"><option value="">Todas</option><option>codeql</option><option>syft</option><option>grype</option></select></label><label>Buscar evidencia<input id="search" placeholder="Regla, paquete o vulnerabilidad"></label></div>
<h3>Estado de ejecución</h3><div class="tablewrap"><table><thead><tr><th>Categoría</th><th>Repositorio</th><th>Herramienta</th><th>Estado</th><th>Resultados</th><th>Detalles</th></tr></thead><tbody id="runs"></tbody></table></div>
<h3>Evidencia</h3><p class="muted" id="evidence-count"></p><div class="tablewrap"><table><thead><tr><th>Categoría</th><th>Repositorio</th><th>Herramienta</th><th>Hallazgo o componente</th><th>Referencia</th></tr></thead><tbody id="evidence"></tbody></table></div>
<div class="pager"><button id="prev">Anterior</button><span id="page"></span><button id="next">Siguiente</button></div></section>
<section class="panel"><h2>Alcance y limitaciones</h2><ul class="notes" id="limitations"></ul></section></main>
<footer>HTML autónomo · cifras calculadas por Python · no se envían datos a servicios externos</footer>
<script type="application/json" id="dataset">__DATA__</script><script>__DASHBOARD_JS__</script></body></html>"""


def generate_html(data: dict, destination: Path) -> Path:
    """Incorpora los datos preparados sin ejecutar texto de los repositorios."""
    # Escapar estos caracteres impide salir del bloque JSON del HTML.
    payload = json.dumps(data, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    destination.parent.mkdir(parents=True, exist_ok=True)
    javascript = (Path(__file__).parent / "assets/dashboard.js").read_text(encoding="utf-8")
    destination.write_text(TEMPLATE.replace("__DASHBOARD_JS__", javascript).replace("__DATA__", payload), encoding="utf-8")
    return destination
