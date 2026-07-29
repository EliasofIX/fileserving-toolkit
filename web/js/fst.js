/* FST client — Archive Light + Transfer Dial */
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  const state = {
    status: null,
    path: "",
    nav: "browse",
    entries: [],
    user: null,
  };

  const CHUNK = 8 * 1024 * 1024; // 8 MiB upload chunks
  let musicMetaSeq = 0;

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "same-origin",
      ...opts,
      headers: {
        ...(opts.body && !(opts.body instanceof Blob) && !(opts.body instanceof ArrayBuffer)
          ? { "Content-Type": "application/json" }
          : {}),
        ...opts.headers,
      },
    });
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("json") ? await res.json() : await res.text();
    if (!res.ok) {
      const err = (data && data.error) || res.statusText;
      throw new Error(err);
    }
    return data;
  }

  function fileUrl(path, stream = false) {
    const q = encodeURIComponent(path);
    return stream ? `/api/stream?path=${q}` : `/api/file?path=${q}`;
  }

  function fmtSize(n) {
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB", "PB"];
    let i = -1;
    let x = n;
    do {
      x /= 1024;
      i++;
    } while (x >= 1024 && i < u.length - 1);
    return `${x.toFixed(x >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
  }

  function fmtTime(sec) {
    if (!isFinite(sec)) return "0:00";
    const s = Math.floor(sec % 60)
      .toString()
      .padStart(2, "0");
    const m = Math.floor(sec / 60) % 60;
    const h = Math.floor(sec / 3600);
    return h > 0 ? `${h}:${m.toString().padStart(2, "0")}:${s}` : `${m}:${s}`;
  }

  /* Theme */
  function initTheme() {
    const saved = localStorage.getItem("fst-theme");
    const prefersDark = matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(saved || (prefersDark ? "dark" : "light"));
    $("#theme-toggle").addEventListener("click", () => {
      setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
  }
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    localStorage.setItem("fst-theme", t);
  }

  /* Auth */
  async function boot() {
    initTheme();
    state.status = await api("/api/status");
    if (state.status.auth_required) {
      try {
        const me = await api("/api/me");
        if (me.username) {
          state.user = me;
          $("#logout-btn").classList.remove("hidden");
        } else {
          showLogin();
          return;
        }
      } catch {
        showLogin();
        return;
      }
    }
    bindChrome();
    navigate("browse", "");
  }

  function showLogin() {
    $("#login").classList.remove("hidden");
    $("#login-form").onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      $("#login-err").textContent = "";
      try {
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({
            username: fd.get("username"),
            password: fd.get("password"),
          }),
        });
        $("#login").classList.add("hidden");
        $("#logout-btn").classList.remove("hidden");
        bindChrome();
        navigate("browse", "");
      } catch (err) {
        $("#login-err").textContent = err.message;
      }
    };
  }

  function bindChrome() {
    $$("[data-nav]").forEach((a) => {
      a.onclick = (e) => {
        e.preventDefault();
        $$("[data-nav]").forEach((x) => x.classList.remove("active"));
        a.classList.add("active");
        navigate(a.dataset.nav, state.path);
      };
    });
    $("#logout-btn").onclick = async () => {
      await api("/api/logout", { method: "POST" });
      location.reload();
    };
    $("#mkdir-btn").onclick = async () => {
      const name = prompt("Folder name");
      if (!name) return;
      const base = state.path || "shared";
      const p = `${base.replace(/\/$/, "")}/${name}`;
      await api("/api/mkdir", { method: "POST", body: JSON.stringify({ path: p }) });
      await refresh();
    };
    $("#file-input").onchange = async (e) => {
      const files = [...e.target.files];
      e.target.value = "";
      for (const f of files) await uploadFile(f);
      await refresh();
    };
    $$("[data-close]").forEach((b) => {
      b.onclick = () => closeStages();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        if (document.fullscreenElement || document.webkitFullscreenElement) return;
        closeStages();
      }
    });
  }

  function closeStages() {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }
    ["photo-stage", "video-stage", "music-stage"].forEach((id) => {
      $(`#${id}`).classList.add("hidden");
    });
    const v = $("#video-el");
    v.pause();
    v.removeAttribute("src");
    v.load();
    const pv = $("#video-preview-el");
    if (pv) {
      pv.pause();
      pv.removeAttribute("src");
      pv.load();
    }
    const preview = $("#video-preview");
    if (preview) preview.classList.add("hidden");
    const a = $("#audio-el");
    a.pause();
  }

  async function navigate(nav, path) {
    state.nav = nav;
    if (path !== undefined) state.path = path;
    await refresh();
  }

  async function refresh() {
    const data = await api(`/api/list?path=${encodeURIComponent(state.path || "")}`);
    state.entries = data.entries || [];
    renderCrumbs();
    if (state.nav === "photos") renderPhotos();
    else if (state.nav === "video") renderVideo();
    else if (state.nav === "music") renderMusic();
    else renderBrowse();
  }

  function renderCrumbs() {
    const el = $("#crumbs");
    const parts = (state.path || "").split("/").filter(Boolean);
    let acc = "";
    const bits = [
      `<a href="#" data-p="">Library</a>`,
      ...parts.map((p) => {
        acc = acc ? `${acc}/${p}` : p;
        const here = acc;
        return `<span>/</span><a href="#" data-p="${here}">${escapeHtml(p)}</a>`;
      }),
    ];
    el.innerHTML = bits.join(" ");
    $$("[data-p]", el).forEach((a) => {
      a.onclick = (e) => {
        e.preventDefault();
        navigate(state.nav, a.dataset.p);
      };
    });
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function renderBrowse() {
    const view = $("#view");
    view.className = "view-browse";
    if (!state.entries.length) {
      view.innerHTML = `<p class="empty">Nothing here. Upload a file or open a folder.</p>`;
      return;
    }
    const ul = document.createElement("ul");
    ul.className = "file-list";
    for (const e of state.entries) {
      const li = document.createElement("li");
      li.innerHTML = `
        <span class="name ${e.is_dir ? "dir" : ""}">${escapeHtml(e.name)}</span>
        <span class="size">${e.is_dir ? "" : fmtSize(e.size)}</span>
        <span class="row-actions">${e.is_dir ? "" : `<button type="button" data-dl>Get</button>`}<button type="button" data-rm>Delete</button></span>`;
      li.onclick = (ev) => {
        if (ev.target.closest("[data-rm],[data-dl]")) return;
        openEntry(e);
      };
      const rm = li.querySelector("[data-rm]");
      if (rm)
        rm.onclick = async (ev) => {
          ev.stopPropagation();
          if (!confirm(`Delete ${e.name}?`)) return;
          await api(`/api/delete?path=${encodeURIComponent(e.path)}`, { method: "DELETE" });
          await refresh();
        };
      const dl = li.querySelector("[data-dl]");
      if (dl)
        dl.onclick = (ev) => {
          ev.stopPropagation();
          downloadLarge(e.path, e.name, e.size).catch((err) => alert(err.message));
        };
      ul.appendChild(li);
    }
    view.innerHTML = "";
    view.appendChild(ul);
  }

  function collect(kind) {
    const out = [];
    function walk(entries) {
      for (const e of entries) {
        if (e.is_dir) continue;
        if (e.kind === kind) out.push(e);
      }
    }
    walk(state.entries);
    return out;
  }

  async function renderPhotos() {
    const view = $("#view");
    view.className = "view-photos";
    // Gather images in current folder; also list nested by soft crawl one level
    let images = collect("image");
    for (const e of state.entries.filter((x) => x.is_dir)) {
      try {
        const d = await api(`/api/list?path=${encodeURIComponent(e.path)}`);
        images = images.concat((d.entries || []).filter((x) => x.kind === "image"));
      } catch (_) {}
    }
    if (!images.length) {
      view.innerHTML = `<p class="empty">No photos in this folder.</p>`;
      return;
    }
    const grid = document.createElement("div");
    grid.className = "photo-grid";
    for (const e of images) {
      const fig = document.createElement("figure");
      const img = document.createElement("img");
      img.loading = "lazy";
      img.alt = e.name;
      img.src = fileUrl(e.path);
      fig.appendChild(img);
      fig.onclick = () => openPhoto(e);
      grid.appendChild(fig);
    }
    view.innerHTML = "";
    view.appendChild(grid);
  }

  async function renderVideo() {
    const view = $("#view");
    view.className = "view-video";
    let videos = collect("video");
    for (const e of state.entries.filter((x) => x.is_dir)) {
      try {
        const d = await api(`/api/list?path=${encodeURIComponent(e.path)}`);
        videos = videos.concat((d.entries || []).filter((x) => x.kind === "video"));
      } catch (_) {}
    }
    if (!videos.length) {
      view.innerHTML = `<p class="empty">No videos in this folder.</p>`;
      return;
    }
    const wall = document.createElement("div");
    wall.className = "video-wall";
    for (const e of videos) {
      const tile = document.createElement("div");
      tile.className = "video-tile";
      tile.innerHTML = `<div class="poster">▶</div><p class="vtitle">${escapeHtml(e.name)}</p>`;
      tile.onclick = () => openVideo(e);
      wall.appendChild(tile);
    }
    view.innerHTML = "";
    view.appendChild(wall);
  }

  async function renderMusic() {
    const view = $("#view");
    view.className = "view-music";
    let tracks = collect("audio");
    for (const e of state.entries.filter((x) => x.is_dir)) {
      try {
        const d = await api(`/api/list?path=${encodeURIComponent(e.path)}`);
        tracks = tracks.concat((d.entries || []).filter((x) => x.kind === "audio"));
      } catch (_) {}
    }
    if (!tracks.length) {
      view.innerHTML = `<p class="empty">No music in this folder.</p>`;
      return;
    }
    const ul = document.createElement("ul");
    ul.className = "file-list music-list";
    for (const e of tracks) {
      const li = document.createElement("li");
      li.innerHTML = `<span class="name">${escapeHtml(e.name)}</span><span class="size">${fmtSize(e.size)}</span>`;
      li.onclick = () => openMusic(e);
      ul.appendChild(li);
    }
    view.innerHTML = "";
    view.appendChild(ul);
  }

  function openEntry(e) {
    if (e.is_dir) {
      navigate(state.nav, e.path);
      return;
    }
    if (e.kind === "image") openPhoto(e);
    else if (e.kind === "video") openVideo(e);
    else if (e.kind === "audio") openMusic(e);
    else {
      const a = document.createElement("a");
      a.href = fileUrl(e.path);
      a.download = e.name;
      a.click();
    }
  }

  function openPhoto(e) {
    closeStages();
    const stage = $("#photo-stage");
    $("#photo-img").src = fileUrl(e.path);
    $("#photo-caption").textContent = e.name;
    stage.classList.remove("hidden");
    stage.focus();
  }

  function openVideo(e) {
    closeStages();
    const stage = $("#video-stage");
    const frame = $("#theater-frame");
    const video = $("#video-el");
    const previewVid = $("#video-preview-el");
    const scrub = $("#video-scrub");
    const preview = $("#video-preview");
    const previewCanvas = $("#video-preview-canvas");
    const previewTime = $("#video-preview-time");
    const timeEl = $("#video-time");
    const playBtn = $("#video-play");
    const backBtn = $("#video-back");
    const fwdBtn = $("#video-fwd");
    const fsBtn = $("#video-fs");
    const src = fileUrl(e.path, true);
    const ctx = previewCanvas.getContext("2d");
    let scrubbing = false;
    let previewSeekToken = 0;
    let previewReady = false;

    $("#video-title").textContent = e.name;
    timeEl.textContent = "0:00 / 0:00";
    scrub.value = 0;
    preview.classList.add("hidden");
    video.src = src;
    previewVid.src = src;
    frame.classList.remove("playing");
    stage.classList.remove("hidden");
    stage.focus();

    const syncPlaying = () => {
      frame.classList.toggle("playing", !video.paused);
    };
    const updateTime = () => {
      const dur = video.duration;
      if (!isFinite(dur) || dur <= 0) {
        timeEl.textContent = `${fmtTime(video.currentTime)} / 0:00`;
        return;
      }
      timeEl.textContent = `${fmtTime(video.currentTime)} / ${fmtTime(dur)}`;
      if (!scrubbing) {
        scrub.value = Math.floor((video.currentTime / dur) * 1000);
      }
    };
    const seekBy = (delta) => {
      if (!isFinite(video.duration)) return;
      video.currentTime = Math.min(
        Math.max(0, video.currentTime + delta),
        video.duration
      );
      updateTime();
    };
    const toggle = () => {
      if (video.paused) video.play().catch(() => {});
      else video.pause();
    };
    const ratioFromClientX = (clientX) => {
      const rect = scrub.getBoundingClientRect();
      if (!rect.width) return 0;
      return Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    };
    const drawPreviewFrame = () => {
      const vw = previewVid.videoWidth;
      const vh = previewVid.videoHeight;
      if (!vw || !vh) return;
      const cw = previewCanvas.width;
      const ch = previewCanvas.height;
      const scale = Math.min(cw / vw, ch / vh);
      const dw = vw * scale;
      const dh = vh * scale;
      ctx.fillStyle = "#111";
      ctx.fillRect(0, 0, cw, ch);
      ctx.drawImage(previewVid, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
    };
    const showPreviewAt = (ratio) => {
      if (!isFinite(video.duration) || video.duration <= 0) return;
      const t = ratio * video.duration;
      previewTime.textContent = fmtTime(t);
      preview.style.left = `${ratio * 100}%`;
      preview.classList.remove("hidden");
      const token = ++previewSeekToken;
      const apply = () => {
        if (token !== previewSeekToken) return;
        if (Math.abs(previewVid.currentTime - t) > 0.05) {
          previewVid.currentTime = t;
        } else if (previewReady) {
          drawPreviewFrame();
        }
      };
      if (previewVid.readyState >= 1) apply();
      else previewVid.addEventListener("loadedmetadata", apply, { once: true });
    };
    const hidePreview = () => {
      if (scrubbing) return;
      preview.classList.add("hidden");
    };

    playBtn.onclick = (ev) => {
      ev.stopPropagation();
      toggle();
    };
    backBtn.onclick = (ev) => {
      ev.stopPropagation();
      seekBy(-10);
    };
    fwdBtn.onclick = (ev) => {
      ev.stopPropagation();
      seekBy(10);
    };
    video.onclick = toggle;
    video.onplay = syncPlaying;
    video.onpause = syncPlaying;
    video.ontimeupdate = updateTime;
    video.onloadedmetadata = updateTime;
    video.onended = () => {
      frame.classList.remove("playing");
      updateTime();
    };

    previewVid.onloadeddata = () => {
      previewReady = true;
    };
    previewVid.onseeked = () => {
      drawPreviewFrame();
    };

    scrub.onpointerdown = () => {
      scrubbing = true;
      const onDocUp = () => {
        scrubbing = false;
        document.removeEventListener("pointerup", onDocUp);
        document.removeEventListener("pointercancel", onDocUp);
        hidePreview();
      };
      document.addEventListener("pointerup", onDocUp);
      document.addEventListener("pointercancel", onDocUp);
    };
    scrub.oninput = () => {
      if (!video.duration) return;
      const ratio = scrub.value / 1000;
      video.currentTime = ratio * video.duration;
      showPreviewAt(ratio);
      updateTime();
    };
    scrub.onmousemove = (ev) => {
      if (!video.duration) return;
      showPreviewAt(ratioFromClientX(ev.clientX));
    };
    scrub.onmouseleave = hidePreview;

    const syncFsBtn = () => {
      const on =
        document.fullscreenElement === frame ||
        document.webkitFullscreenElement === frame;
      fsBtn.setAttribute("aria-label", on ? "Exit fullscreen" : "Fullscreen");
      fsBtn.title = on ? "Exit fullscreen" : "Fullscreen";
    };
    fsBtn.onclick = async (ev) => {
      ev.stopPropagation();
      try {
        if (document.fullscreenElement === frame) {
          await document.exitFullscreen();
        } else if (frame.requestFullscreen) {
          await frame.requestFullscreen();
        } else if (frame.webkitRequestFullscreen) {
          frame.webkitRequestFullscreen();
        }
      } catch (_) {}
      syncFsBtn();
    };
    document.onfullscreenchange = syncFsBtn;
    syncFsBtn();
    syncPlaying();
  }

  function openMusic(e) {
    closeStages();
    const stage = $("#music-stage");
    const audio = $("#audio-el");
    const artistEl = $("#music-artist");
    $("#music-title").textContent = e.name.replace(/\.[^.]+$/, "");
    $("#music-filename").textContent = e.name;
    artistEl.textContent = "";
    artistEl.hidden = true;
    audio.src = fileUrl(e.path);
    stage.classList.remove("hidden");
    stage.focus();
    audio.play().catch(() => {});

    const metaReq = ++musicMetaSeq;
    fetch(`/api/audio/meta?path=${encodeURIComponent(e.path)}`, {
      credentials: "same-origin",
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (metaReq !== musicMetaSeq) return;
        const artist = data && data.artist;
        if (typeof artist === "string" && artist.trim()) {
          artistEl.textContent = artist.trim();
          artistEl.hidden = false;
        }
      })
      .catch(() => {});

    const btn = $("#music-play");
    const scrub = $("#music-scrub");
    const time = $("#music-time");
    const syncBtn = () => {
      btn.textContent = audio.paused ? "Play" : "Pause";
    };
    btn.onclick = () => {
      if (audio.paused) audio.play();
      else audio.pause();
      syncBtn();
    };
    audio.onplay = syncBtn;
    audio.onpause = syncBtn;
    audio.ontimeupdate = () => {
      if (!audio.duration) return;
      scrub.value = Math.floor((audio.currentTime / audio.duration) * 1000);
      time.textContent = `${fmtTime(audio.currentTime)} / ${fmtTime(audio.duration)}`;
    };
    scrub.oninput = () => {
      if (!audio.duration) return;
      audio.currentTime = (scrub.value / 1000) * audio.duration;
    };
    syncBtn();
  }

  /* Transfer Dial */
  function showDial(label) {
    $("#transfer-dial").classList.remove("hidden");
    $("#dial-label").textContent = label;
  }
  function updateDial(done, total, detail) {
    const pct = total ? Math.min(100, (done / total) * 100) : 0;
    $("#dial-pct").textContent = `${pct < 10 ? pct.toFixed(1) : Math.floor(pct)}%`;
    $("#dial-fill").style.width = `${pct}%`;
    $("#dial-detail").textContent = detail || `${fmtSize(done)} / ${fmtSize(total)}`;
  }
  function hideDial() {
    $("#transfer-dial").classList.add("hidden");
  }

  async function uploadFile(file) {
    const base = state.path || "shared";
    const dest = `${base.replace(/\/$/, "")}/${file.name}`;
    const large = file.size >= (state.status?.large_threshold || 100 * 1024 * 1024);
    if (large) showDial("Upload");

    const init = await api("/api/upload/init", {
      method: "POST",
      body: JSON.stringify({ path: dest, size: file.size }),
    });
    let offset = init.offset || 0;
    const id = init.id;

    while (offset < file.size) {
      const end = Math.min(offset + CHUNK, file.size);
      const blob = file.slice(offset, end);
      const res = await fetch(`/api/upload/${id}`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "X-FST-Offset": String(offset) },
        body: blob,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "upload failed");
      offset = data.offset;
      if (large) updateDial(offset, file.size, file.name);
    }

    if (large) {
      $("#dial-label").textContent = "Sealing";
      updateDial(file.size, file.size, file.name);
    }
    await api(`/api/upload/${id}/complete`, { method: "POST" });
    if (large) {
      updateDial(file.size, file.size, "Done");
      setTimeout(hideDial, 600);
    }
  }

  /* Large download via Transfer Dial (fetch + progressive save when possible) */
  async function downloadLarge(path, name, size) {
    const large = size >= (state.status?.large_threshold || 100 * 1024 * 1024);
    if (!large) {
      const a = document.createElement("a");
      a.href = fileUrl(path);
      a.download = name;
      a.click();
      return;
    }
    showDial("Download");
    const total = size || 0;

    // Stream to disk when the File System Access API is available (TB-safe).
    if (window.showSaveFilePicker) {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        const writable = await handle.createWritable();
        const res = await fetch(fileUrl(path), { credentials: "same-origin" });
        if (!res.ok) throw new Error("download failed");
        const len = Number(res.headers.get("content-length")) || total;
        const reader = res.body.getReader();
        let done = 0;
        for (;;) {
          const { value, done: d } = await reader.read();
          if (d) break;
          await writable.write(value);
          done += value.length;
          updateDial(done, len || done, name);
        }
        await writable.close();
        setTimeout(hideDial, 500);
        return;
      } catch (e) {
        if (e.name === "AbortError") {
          hideDial();
          return;
        }
        // fall through
      }
    }

    // Fallback: browser download manager (no RAM blowup)
    updateDial(0, total, "Handing off to browser…");
    const a = document.createElement("a");
    a.href = fileUrl(path);
    a.download = name;
    a.click();
    setTimeout(hideDial, 900);
  }

  // Expose for future; browse uses anchor for small files
  window.fstDownloadLarge = downloadLarge;

  boot().catch((e) => {
    console.error(e);
    document.body.innerHTML = `<p style="font-family:Helvetica,Arial,sans-serif;padding:2rem">FST failed to start: ${escapeHtml(
      e.message
    )}</p>`;
  });
})();
