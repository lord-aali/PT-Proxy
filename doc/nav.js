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
    ["FTP", "ftp.html"]
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
  if (nav) nav.innerHTML = html;
})();
