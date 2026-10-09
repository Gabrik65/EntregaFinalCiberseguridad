"""Genera una plantilla de afiche A0 y un guion de presentación en español."""

import html
from pathlib import Path


def write_poster(data: dict, directory: Path, *, reporter_mode: str = "pending") -> None:
    """Crea materiales de presentación con cifras medidas y el estado de Reporter."""
    if reporter_mode not in {"pending", "simulated", "openrouter"}:
        raise ValueError("Modo de Reporter desconocido para el afiche")
    directory.mkdir(parents=True, exist_ok=True)
    summary = data["summary"]
    organization = data.get("organization") or "organización seleccionada"
    reporter_status = {
        "pending": "El informe de Reporter aún no se ha verificado en una ejecución.",
        "simulated": "Reporter usó un cliente simulado determinista; aún falta usar un modelo real.",
        "openrouter": "Reporter generó un informe con OpenRouter; sus afirmaciones requieren revisión humana.",
    }[reporter_mode]

    # Traduce los estados sin modificar los códigos guardados en el dataset.
    state_labels = {"success": "completado", "success_empty": "sin resultados",
                    "partial": "parcial", "failed": "fallido",
                    "skipped": "omitido", "unsupported": "no compatible"}
    # Escapa etiquetas provenientes de herramientas antes de insertarlas en HTML.
    coverage = "".join(
        f"<tr><td>{html.escape(tool)}</td><td>"
        f"{html.escape(', '.join(f'{state_labels.get(state, state)}: {count}' for state, count in states.items()))}</td></tr>"
        for tool, states in summary["coverage"].items()
    )
    poster = f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Afiche A0 · Seguridad del software</title>
<style>@page{{size:841mm 1189mm;margin:15mm}}*{{box-sizing:border-box}}body{{margin:0;background:#e8ece8;font-family:Arial,sans-serif;color:#14362d}}.poster{{max-width:1150px;margin:30px auto;padding:55px;background:#fff}}h1{{font-size:56px;line-height:1.05;margin:25px 0}}h2{{font-size:28px;border-top:4px solid #20836a;padding-top:18px}}p,li,td{{font-size:19px;line-height:1.55}}.top{{background:#12362c;color:white;padding:35px}}.tag{{text-transform:uppercase;letter-spacing:3px;font-size:15px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:25px 0}}.stat{{background:#eaf3ed;padding:20px}}.stat strong{{font-size:38px;display:block}}.columns{{display:grid;grid-template-columns:1fr 1fr;gap:38px}}table{{border-collapse:collapse;width:100%}}td{{border-bottom:1px solid #ccd8cc;padding:12px}}.footer{{background:#edf3ee;padding:20px;margin-top:30px}}@media print{{body{{background:white}}.poster{{max-width:none;width:811mm;min-height:1159mm;margin:0;padding:30mm}}h1{{font-size:95pt}}h2{{font-size:45pt}}p,li,td{{font-size:28pt}}.tag{{font-size:23pt}}.stat strong{{font-size:65pt}}.stat{{font-size:25pt;padding:12mm}}.columns{{gap:25mm}}.top{{padding:20mm}}.footer{{margin-top:25mm;padding:15mm}}}}</style></head><body><article class="poster">
<header class="top"><div class="tag">Proyecto semestral de ciberseguridad · {html.escape(organization)}</div><h1>¿Qué revela el análisis de seguridad de los repositorios?</h1><p>El código, las dependencias y la cobertura orientan la revisión.</p></header>
<section class="stats"><div class="stat"><strong>{summary['repositories']}</strong>repositorios registrados</div><div class="stat"><strong>{summary['code_findings']}</strong>alertas de código</div><div class="stat"><strong>{summary['dependency_findings']}</strong>coincidencias de dependencias</div><div class="stat"><strong>{summary['components']}</strong>componentes</div></section>
<div class="columns"><section><h2>Pregunta y muestra</h2><p>Examinamos repositorios públicos de {html.escape(organization)} que no están archivados ni son forks. Los commits fijados hacen reproducible la muestra. Objetivo: {summary['expected_repositories']} repositorios.</p><h2>Método</h2><ol><li><b>Miner:</b> obtiene revisiones fijadas; CodeQL detecta alertas de código, Syft inventaría componentes y Grype busca coincidencias con vulnerabilidades conocidas de dependencias.</li><li><b>Analyzer:</b> valida la evidencia, elimina duplicados exactos y calcula estadísticas reproducibles.</li><li><b>Visualizer:</b> presenta hallazgos y estados de las herramientas en un panel HTML local.</li><li><b>Reporter:</b> analiza este proyecto y genera un informe con referencias verificadas.</li></ol></section>
<section><h2>Cobertura observada</h2><table>{coverage}</table><h2>Interpretación</h2><p>Los conteos señalan elementos para revisar; no demuestran que sean explotables. Las escalas de severidad de CodeQL y Grype se mantienen separadas.</p><p>Los análisis fallidos, lenguajes no compatibles e inventarios vacíos limitan las conclusiones. No demuestran ausencia de vulnerabilidades.</p><h2>Estado de Reporter</h2><p>{html.escape(reporter_status)}</p></section></div>
<footer class="footer"><p><b>Reproducibilidad:</b> manifiesto con commits fijados, versiones de herramientas, metadatos de la base de vulnerabilidades, evidencia original y notebook ejecutado.</p><p><b>Equipo:</b> [Agregar nombres] · <b>Repositorio público:</b> [Agregar enlace tras publicarlo]</p><p>Esta es una plantilla A0 digital. Después de elaborar el afiche físico, guarda una fotografía legible en PDF dentro del repositorio.</p></footer></article></body></html>'''
    (directory / "poster-a0.html").write_text(poster, encoding="utf-8")

    # El guion usa los mismos totales calculados que el afiche.
    speech = f"""# Guion de presentación — aproximadamente 2 a 3 minutos

Nuestro proyecto examina qué puede revelar el análisis de código y dependencias sobre la seguridad de repositorios públicos.

Seleccionamos {organization} y fijamos una muestra de {summary['expected_repositories']} repositorios públicos que no están archivados ni son forks. Guardamos sus commits para poder repetir la selección.

La solución tiene cuatro componentes. Miner prepara los repositorios y ejecuta tres herramientas. CodeQL identifica alertas de código. Syft produce un inventario de componentes y Grype busca coincidencias con vulnerabilidades conocidas en dependencias.

Analyzer valida los resultados y calcula estadísticas con Python. Visualizer los presenta en una página HTML local con filtros por repositorio y herramienta. Reporter analiza nuestro propio proyecto y produce un informe vinculado a la evidencia.

Esta ejecución registró {summary['repositories']} repositorios, {summary['code_findings']} alertas de código, {summary['dependency_findings']} coincidencias con vulnerabilidades de dependencias y {summary['components']} componentes. La tabla de cobertura del afiche muestra cuántos análisis terminaron, fallaron o no fueron compatibles.

Estos conteos no representan vulnerabilidades confirmadas. Cada alerta requiere revisión, y un resultado vacío no demuestra que un proyecto sea seguro. También mantenemos separadas las escalas de severidad de cada herramienta.

{reporter_status}

Entregamos el manifiesto con commits fijados, la evidencia original, un notebook ejecutado y el visualizador. Así se puede rastrear cada resultado hasta su origen y distinguir las limitaciones del análisis de la ausencia de hallazgos.
"""
    (directory / "presentation-script.md").write_text(speech, encoding="utf-8")
