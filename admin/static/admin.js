// NetSentinel admin — progressive enhancement over server-rendered forms.
// No build step; the pages work without JS, this just saves a reload.

async function api(path, options = {}) {
  const res = await fetch('/api' + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) {
    window.location.href = '/admin/login';
    throw new Error('unauthenticated');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}

function flash(message, kind = 'ok') {
  let el = document.getElementById('flash');
  if (!el) {
    el = document.createElement('div');
    el.id = 'flash';
    document.querySelector('.main')?.prepend(el);
  }
  el.className = 'flash ' + kind;
  el.textContent = message;
  setTimeout(() => el.remove(), 4000);
}

async function on(selector, event, handler) {
  document.querySelectorAll(selector).forEach((el) =>
    el.addEventListener(event, handler)
  );
}

// ---- Telegram users ----
async function addUser(form) {
  const body = {
    telegram_user_id: Number(form.telegram_user_id.value),
    username: form.username.value || null,
    role: form.role.value,
  };
  try {
    await api('/users', { method: 'POST', body: JSON.stringify(body) });
    flash('User added.');
    form.reset();
  } catch (e) {
    flash(e.message, 'bad');
  }
}

async function patchUser(id, patch) {
  try {
    await api('/users/' + id, { method: 'PATCH', body: JSON.stringify(patch) });
    flash('Updated.');
  } catch (e) {
    flash(e.message, 'bad');
  }
}

async function deleteUser(id) {
  if (!confirm('Remove user ' + id + '? This cannot be undone.')) return;
  try {
    await api('/users/' + id + '?confirm=true', { method: 'DELETE' });
    flash('User removed.');
    setTimeout(() => location.reload(), 600);
  } catch (e) {
    flash(e.message, 'bad');
  }
}

// ---- Targets ----
async function addTarget(form) {
  const body = {
    name: form.name.value,
    value: form.value.value,
    group: form.group?.value || null,
  };
  try {
    await api('/targets', { method: 'POST', body: JSON.stringify(body) });
    flash('Target added.');
    setTimeout(() => location.reload(), 500);
  } catch (e) {
    flash(e.message, 'bad');
  }
}

async function purgeTarget(id, name) {
  const msg =
    'Permanently delete "' + name + '" and ALL of its scan history?\n\n' +
    'This destroys the security record and cannot be undone.';
  if (!confirm(msg)) return;
  try {
    await api('/targets/' + id + '?confirm=true', { method: 'DELETE' });
    flash('Target purged.');
    setTimeout(() => location.reload(), 600);
  } catch (e) {
    // The API refuses without confirmation; show its explanation.
    flash(e.message, 'bad');
  }
}

// ---- Settings ----
async function saveSettings(form) {
  const values = {};
  new FormData(form).forEach((v, k) => {
    values[k] = v;
  });
  try {
    const res = await api('/settings', {
      method: 'PATCH',
      body: JSON.stringify({ values }),
    });
    flash('Saved: ' + Object.keys(res.settings).join(', '));
  } catch (e) {
    flash(e.message, 'bad');
  }
}

// ---- Toggle switches inside tables ----
on('[data-user-toggle]', 'change', (e) => {
  const id = e.target.dataset.userId;
  patchUser(id, { enabled: e.target.checked });
});

on('[data-user-role]', 'change', (e) => {
  patchUser(e.target.dataset.userId, { role: e.target.value });
});

on('[data-user-lang]', 'change', (e) => {
  patchUser(e.target.dataset.userId, { language: e.target.value });
});

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('add-user-form');
  if (form) form.addEventListener('submit', (e) => { e.preventDefault(); addUser(form); });

  const tform = document.getElementById('add-target-form');
  if (tform) tform.addEventListener('submit', (e) => { e.preventDefault(); addTarget(tform); });

  const sform = document.getElementById('settings-form');
  if (sform) sform.addEventListener('submit', (e) => { e.preventDefault(); saveSettings(sform); });
});