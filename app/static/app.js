const $ = (s) => document.querySelector(s);
const projectList = $('#projectList');
let projects = [];
let activeProject = null;
async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}
function escapeHtml(value = '') { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function notify(message) { const toast = $('#toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 2600); }
function showError(target, message) { target.textContent = message; }
function renderProjects() {
  const scans = projects.map(p => p.latest_scan).filter(Boolean);
  const endpoints = scans.reduce((sum, s) => sum + s.endpoint_count, 0);
  const findings = scans.reduce((sum, s) => sum + s.findings_count, 0);
  const critical = scans.reduce((sum, s) => sum + (s.summary?.by_severity?.critical || 0), 0);
  $('#projectCount').textContent = projects.length;
  $('#endpointCount').textContent = endpoints;
  $('#findingCount').textContent = findings;
  $('#criticalCount').textContent = critical;
  if (!projects.length) {
    projectList.innerHTML = `<div class="empty"><div class="empty-icon">◇</div><h3>Your API portfolio starts here</h3><p>Create a project, then upload an OpenAPI file to run your first security review.</p><button class="button primary" id="emptyCreate">＋ &nbsp;Create a project</button></div>`;
    $('#emptyCreate').onclick = openProject;
    return;
  }
  projectList.innerHTML = projects.map(p => `<article class="project-row"><div><div class="project-name">${escapeHtml(p.name)}</div><div class="project-desc">${escapeHtml(p.description || 'No description')}</div></div><div class="project-api">${p.latest_scan ? `${p.latest_scan.endpoint_count} endpoints<small>${escapeHtml(p.latest_scan.api_title)} · ${new Date(p.latest_scan.created_at).toLocaleDateString()}</small>` : 'No scans yet'}</div><div class="project-actions"><button class="mini-btn scan" data-scan="${p.id}">＋ Scan spec</button><button class="mini-btn" data-report="${p.latest_scan?.id || ''}" ${p.latest_scan ? '' : 'disabled'}>Report</button></div></article>`).join('');
  projectList.querySelectorAll('[data-scan]').forEach(b => b.onclick = () => openScan(Number(b.dataset.scan)));
  projectList.querySelectorAll('[data-report]').forEach(b => b.onclick = () => { if (b.dataset.report) window.open(`/api/scans/${b.dataset.report}/report`, '_blank'); });
}
async function loadProjects() { projectList.innerHTML = '<div class="loading">Loading workspace…</div>'; try { projects = await api('/api/projects'); renderProjects(); } catch (e) { projectList.innerHTML = `<div class="empty"><h3>Could not load workspace</h3><p>${escapeHtml(e.message)}</p><button class="button secondary" id="tryAgain">Retry</button></div>`; $('#tryAgain').onclick = loadProjects; } }
function openProject() { $('#formError').textContent = ''; $('#projectForm').reset(); $('#projectDialog').showModal(); }
function openScan(id) { activeProject = projects.find(p => p.id === id); $('#scanTitle').textContent = activeProject.name; $('#scanError').textContent = ''; $('#scanResults').innerHTML = ''; $('#specFile').value = ''; $('#scanDialog').showModal(); }
$('#newProjectBtn').onclick = openProject;
$('#navProjects').onclick = () => document.querySelector('.section-row').scrollIntoView({behavior:'smooth'});
$('#navDashboard').onclick = () => window.scrollTo({top:0,behavior:'smooth'});
$('#refreshBtn').onclick = loadProjects;
document.querySelectorAll('[data-close]').forEach(b => b.onclick = () => b.closest('dialog').close());
$('#projectForm').onsubmit = async event => { event.preventDefault(); const data = new FormData(event.currentTarget); try { await api('/api/projects', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:data.get('name'),description:data.get('description')})}); $('#projectDialog').close(); await loadProjects(); notify('Project created'); } catch(e) { showError($('#formError'),e.message); } };
$('#dropzone').onclick = e => { if (e.target.id !== 'specFile') $('#specFile').click(); };
$('#specFile').onchange = async event => { const file = event.target.files[0]; if (!file || !activeProject) return; $('#scanError').textContent = ''; $('#scanResults').innerHTML = '<div class="loading">Reviewing specification…</div>'; const data = new FormData(); data.append('file',file); try { const result = await api(`/api/projects/${activeProject.id}/scans`,{method:'POST',body:data}); const counts = result.summary.by_severity; const ordered = [...result.findings].sort((a,b) => ['critical','high','medium','low'].indexOf(a.severity)-['critical','high','medium','low'].indexOf(b.severity)); $('#scanResults').innerHTML = `<div class="scan-result"><b>${escapeHtml(result.api_title)}</b> <span style="color:#9ba5b6">v${escapeHtml(result.api_version)} · ${result.endpoint_count} routes</span><p style="margin:9px 0 0;color:#aab4c4">${result.findings_count} findings · <span style="color:#ff9a9e">${counts.critical} critical</span> · ${counts.high} high · ${counts.medium} medium · ${counts.low} low</p>${ordered.slice(0,8).map(f=>`<div class="finding"><span class="severity ${f.severity}">${f.severity}</span><strong>${escapeHtml(f.title)}</strong><small>${escapeHtml(f.method)} ${escapeHtml(f.path)} — ${escapeHtml(f.remediation)}</small></div>`).join('')}<p style="margin-bottom:0"><a style="color:#9db7ff" target="_blank" href="/api/scans/${result.id}/report">Download full JSON report ↗</a></p></div>`; await loadProjects(); notify('Security review complete'); } catch(e) { $('#scanResults').innerHTML = ''; showError($('#scanError'),e.message); } };
loadProjects();
