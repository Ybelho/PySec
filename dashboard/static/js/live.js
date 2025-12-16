window.PYSEC = window.PYSEC || {};
PYSEC.lastTimestamp = ""; // ISO

PYSEC.toast = function (msg) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2200);
};

