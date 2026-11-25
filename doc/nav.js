(function () {
  var items = [
    ["Overview", "index.html"],
    ["Config & tags", "config.html"],
    ["Forward & reverse", "forward-reverse.html"],
    ["Mux layer", "muxpipe.html"],
    ["socks", "socks.html"],
    ["http", "http.html"],
    ["external", "external.html"],
    ["obfs2 / obfs3 / obfs4", "obfs.html"],
    ["DPI", "dpi.html"],
    ["Snowflake", "snowflake.html"],
    ["FTP", "ftp.html"],
    ["TCP / UDP carrier", "carrier.html"],
    ["GRE", "gre.html"],
    ["WebRTC", "webrtc.html"],
    ["MoQ", "moq.html"],
    ["Custom WG", "cwg.html"],
    ["DNS", "dns.html"]
  ];
  var file = (location.pathname.split("/").pop() || "index.html").toLowerCase();
  var html = '<h1>PT Proxy wiki</h1><div class="sub">Instructions and implementation</div>';
  var lastGroup = "";
  items.forEach(function (it, i) {
    var group = i < 4 ? "Core" : i < 7 ? "Services" : "Tunnels";
    if (group !== lastGroup) {
      html += '<div class="group">' + group + "</div>";
      lastGroup = group;
    }
    var active = file === it[1] || (file === "" && it[1] === "index.html") ? " active" : "";
    html += '<a class="' + active.trim() + '" href="' + it[1] + '">' + it[0] + "</a>";
  });
  html += '<div class="group">Repo</div><a href="../README.md">README</a><a href="../config-builder.html">Config builder</a>';
  var nav = document.getElementById("nav");
  if (!nav) return;
  nav.innerHTML = '<button type="button" class="nav-toggle" aria-expanded="false" aria-controls="nav-panel">Menu</button><div class="nav-panel" id="nav-panel">' + html + "</div>";
  var toggle = nav.querySelector(".nav-toggle");
  function setOpen(open) {
    nav.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.textContent = open ? "Close menu" : "Menu";
  }
  toggle.addEventListener("click", function () {
    setOpen(!nav.classList.contains("open"));
  });
  nav.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      setOpen(false);
    });
  });
  document.querySelectorAll("main table").forEach(function (table) {
    var parent = table.parentNode;
    if (!parent || (parent.classList && parent.classList.contains("table-scroll"))) return;
    var wrap = document.createElement("div");
    wrap.className = "table-scroll";
    parent.insertBefore(wrap, table);
    wrap.appendChild(table);
  });
})();
