const output = document.getElementById('admin-output');

function show(data) {
  output.textContent = JSON.stringify(data, null, 2);
}

document.getElementById('admin-login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const res = await fetch('/admin/login', { method: 'POST', body: formData });
  show(await res.json());
});
