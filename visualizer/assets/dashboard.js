// Lee los datos generados por Python sin insertar texto del escáner como HTML.
const data=JSON.parse(document.getElementById('dataset').textContent);
document.title = `Observatorio de seguridad · ${data.organization || 'repositorios públicos'}`;
const $ = id => document.getElementById(id);
const node = (tag, text) => {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
};
const labels={success:'Completado',success_empty:'Sin resultados',failed:'Fallido',skipped:'Omitido',unsupported:'No compatible',partial:'Parcial'};
const severityLabels={error:'Error',warning:'Advertencia',note:'Nota',none:'Ninguno',
  critical:'Crítica',high:'Alta',medium:'Media',low:'Baja',negligible:'Insignificante',unknown:'Desconocida'};
const severityLabel = value => severityLabels[String(value).toLowerCase()] || value;
const summary=data.summary;
// Las tarjetas y la cobertura incluyen los análisis fallidos en el denominador.
for (const [name, value] of [
  ['Repositorios', summary.repositories],
  ['Alertas de código', summary.code_findings],
  ['Coincidencias en dependencias', summary.dependency_findings],
  ['Componentes', summary.components]
]) {
  const card = node('div', '');
  card.className = 'card';
  card.append(node('small', name), node('strong', value));
  $('cards').append(card);
}
$('coverage-note').textContent = `${summary.repositories} de ${summary.expected_repositories} repositorios esperados. Un análisis fallido nunca equivale a ausencia de vulnerabilidades.`;
for (const [tool, states] of Object.entries(summary.coverage)) {
  const paragraph = node('p', `${tool.toUpperCase()} · `);
  for (const [status, count] of Object.entries(states)) {
    const badge = node('span', `${labels[status] || status}: ${count}`);
    badge.className = 'badge ' + (['failed', 'partial'].includes(status) ? 'bad'
      : (['skipped', 'unsupported'].includes(status) ? 'neutral' : ''));
    badge.style.margin = '3px';
    paragraph.append(badge);
  }
  $('coverage').append(paragraph);
}
// Los gráficos mantienen separadas las escalas de severidad del código y las dependencias.
function chart(kind, target) {
  const counts = {};
  for (const item of data.evidence.filter(item => item.kind === kind)) {
    const severity = item.detail.severity || 'Sin nivel';
    counts[severity] = (counts[severity] || 0) + 1;
  }
  if (!Object.keys(counts).length) {
    $(target).append(node('p', 'No hay hallazgos registrados; revisa la cobertura.'));
    return;
  }
  const maximum = Math.max(...Object.values(counts));
  for (const [label, count] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    const row = node('div', '');
    row.className = 'barrow';
    const track = node('div', '');
    track.className = 'track';
    const bar = node('div', '');
    bar.className = 'bar';
    bar.style.width = (100 * count / maximum) + '%';
    track.append(bar);
    row.append(node('small', severityLabel(label)), track, node('strong', count));
    $(target).append(row);
  }
}
chart('code', 'code-chart');
chart('dependency', 'dep-chart');
const categoryOf = repository => data.repositories.find(item => item.repository === repository)?.category || 'Sin categoría';
const categories = [...new Set(data.repositories.map(item => item.category || 'Sin categoría'))].sort();
for (const category of categories) {
  const option = node('option', category);
  option.value = category;
  $('category').append(option);
}
function categoryChart(kind, tool, target) {
  const counts = categories.map(category => ({
    category,
    repositories: data.repositories.filter(item => (item.category || 'Sin categoría') === category),
    count: data.evidence.filter(item => item.kind === kind && categoryOf(item.repository) === category).length
  }));
  const maximum = Math.max(1, ...counts.map(item => item.count));
  for (const item of counts) {
    const covered = item.repositories.filter(repo => repo.tools.some(result =>
      result.tool === tool && ['success', 'success_empty'].includes(result.status))).length;
    const row = node('div', '');
    row.className = 'barrow';
    const track = node('div', '');
    track.className = 'track';
    const bar = node('div', '');
    bar.className = 'bar';
    bar.style.width = (100 * item.count / maximum) + '%';
    track.append(bar);
    row.append(node('small', `${item.category} · ${covered}/${item.repositories.length}`),
      track, node('strong', item.count));
    $(target).append(row);
  }
}
categoryChart('code', 'codeql', 'category-code');
categoryChart('dependency', 'grype', 'category-dependency');
for (const repository of data.repositories) {
  const option = node('option', repository.repository);
  option.value = repository.repository;
  $('repository').append(option);
}
for (const limitation of data.limitations) $('limitations').append(node('li', limitation));
let page = 0;
const pageSize = 40;
// Los filtros actualizan ambas tablas; la paginación mantiene fluida la vista.
function render() {
  const category = $('category').value;
  const repository = $('repository').value;
  const tool = $('tool').value;
  const search = $('search').value.toLowerCase();
  $('runs').replaceChildren();
  for (const record of data.repositories.filter(item =>
    (!category || (item.category || 'Sin categoría') === category) &&
    (!repository || item.repository === repository))) {
    for (const result of record.tools.filter(item => !tool || item.tool === tool)) {
      const row = node('tr', '');
      for (const value of [record.category || 'Sin categoría', record.repository,
        result.tool, labels[result.status] || result.status,
        result.count, result.error || result.warnings.join('; ') || '—']) {
        row.append(node('td', value));
      }
      $('runs').append(row);
    }
  }

  // La búsqueda revisa la evidencia; la tabla de estados siempre muestra la cobertura.
  const items = data.evidence.filter(item =>
    (!category || categoryOf(item.repository) === category) &&
    (!repository || item.repository === repository) &&
    (!tool || item.tool === tool) &&
    (!search || JSON.stringify(item.detail).toLowerCase().includes(search)));
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  page = Math.min(page, pages - 1);
  $('evidence-count').textContent = `${items.length} registros coinciden con los filtros.`;
  $('evidence').replaceChildren();
  for (const item of items.slice(page * pageSize, (page + 1) * pageSize)) {
    const detail = item.detail;
    const description = item.kind === 'code'
      ? `${detail.rule_id} · ${detail.file}:${detail.start_line}`
      : item.kind === 'dependency'
        ? `${detail.vulnerability_id} · ${detail.package_name} ${detail.package_version} · ${severityLabel(detail.severity)}`
        : `${detail.name} ${detail.version || '(versión no identificada)'}`;
    const row = node('tr', '');
    for (const value of [categoryOf(item.repository), item.repository, item.tool, description, item.id]) {
      row.append(node('td', value));
    }
    $('evidence').append(row);
  }
  $('page').textContent = `${page + 1} / ${pages}`;
  $('prev').disabled = page === 0;
  $('next').disabled = page >= pages - 1;
}
for (const id of ['category', 'repository', 'tool', 'search']) {
  $(id).addEventListener('input', () => { page = 0; render(); });
}
$('prev').onclick = () => { page--; render(); };
$('next').onclick = () => { page++; render(); };
render();
