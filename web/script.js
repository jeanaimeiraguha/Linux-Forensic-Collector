/*
 * LFC landing page enhancements.
 *
 * SECURITY: this file only READS display data (SHA256SUMS.txt) and handles
 * copy-to-clipboard buttons. It never evaluates downloaded content, never
 * auto-downloads anything and never executes scripts from the network.
 */
(function () {
  "use strict";

  // --- Publish checksums for display (read-only) ---------------------------
  var panel = document.getElementById("checksum-panel");
  var list = document.getElementById("checksum-list");

  function loadChecksums() {
    if (!panel || !list) return;
    if (!window.fetch) return; // graceful degradation: manual instructions remain
    fetch("SHA256SUMS.txt", { cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.text();
      })
      .then(function (text) {
        var lines = text.split("\n").filter(function (l) { return l.trim() !== ""; });
        if (lines.length === 0) throw new Error("empty");
        list.textContent = text.trim();
        panel.hidden = false;
      })
      .catch(function () {
        // File not published yet or opened via file:// — keep manual instructions only.
        if (panel) panel.hidden = true;
      });
  }

  // --- Copy buttons --------------------------------------------------------
  function copyText(text, button, originalLabel) {
    function done(ok) {
      button.textContent = ok ? "Copied!" : "Copy failed";
      window.setTimeout(function () {
        button.textContent = originalLabel;
      }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { done(true); },
        function () { done(false); }
      );
    } else {
      done(false);
    }
  }

  function wireCopy() {
    var btn = document.getElementById("copy-checksums");
    if (!btn) return;
    var label = btn.textContent;
    btn.addEventListener("click", function () {
      var text = list ? list.textContent : "";
      if (text) copyText(text, btn, label);
    });
  }

  // --- Optional file-size display (read-only HEAD requests) ---------------
  function loadSizes() {
    if (!window.fetch) return;
    ["downloads/lfc-1.0.0.tar.gz", "downloads/lfc.sh"].forEach(function (url, idx) {
      var el = document.getElementById(idx === 0 ? "size-tarball" : "size-script");
      if (!el) return;
      fetch(url, { method: "HEAD" })
        .then(function (res) {
          if (!res.ok) return null;
          var len = parseInt(res.headers.get("content-length") || "0", 10);
          if (!len) return null;
          if (len > 1048576) el.textContent = (len / 1048576).toFixed(1) + " MiB";
          else el.textContent = Math.max(1, Math.round(len / 1024)) + " KiB";
        })
        .catch(function () { /* leave placeholder */ });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    loadChecksums();
    wireCopy();
    loadSizes();
  });
})();
