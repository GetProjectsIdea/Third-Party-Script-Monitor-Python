// First-party app code (demo)
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('year');
  if (el) { el.textContent = new Date().getFullYear(); }
});
