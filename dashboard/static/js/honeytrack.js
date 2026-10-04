/**
 * HoneyTrack - Live Threat Operations & Intelligence Dashboard
 * Integrates Lovable's UI design with HoneyTrack's live Python/Flask backend and SQLite database.
 */
(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const escapeHtml = (value) =>
    String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[char]));

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Only run on dashboard page
  if (document.body.dataset.page !== 'dashboard') return;

  // Country name to ISO-2 code mapping
  const COUNTRY_CODES = {
    'united states': 'US',
    'united states of america': 'US',
    'usa': 'US',
    'china': 'CN',
    'russia': 'RU',
    'russian federation': 'RU',
    'germany': 'DE',
    'brazil': 'BR',
    'india': 'IN',
    'netherlands': 'NL',
    'united kingdom': 'GB',
    'great britain': 'GB',
    'uk': 'GB',
    'singapore': 'SG',
    'turkey': 'TR',
    'south korea': 'KR',
    'korea': 'KR',
    'australia': 'AU',
    'france': 'FR',
    'kenya': 'KE',
    'nigeria': 'NG',
    'romania': 'RO'
  };

  const AVAILABLE_FLAGS = new Set([
    'AU', 'BR', 'CN', 'DE', 'FR', 'GB', 'IN', 'KE', 'KR', 'NG', 'NL', 'RO', 'RU', 'SG', 'TR', 'US'
  ]);

  function getCountryCode(countryName) {
    if (!countryName) return 'US';
    const clean = countryName.toLowerCase().trim();
    if (clean.length === 2) return clean.toUpperCase();
    return COUNTRY_CODES[clean] || 'US';
  }

  function flagImage(code) {
    const safeCode = (code || 'US').toUpperCase();
    if (AVAILABLE_FLAGS.has(safeCode)) {
      return `<img class="flag" src="/static/flags/${safeCode}.svg" alt="${safeCode}" onerror="this.style.display='none'">`;
    }
    return `<span class="flag-fallback" style="display:inline-block;padding:0 3px;font-size:9px;font-family:var(--font-mono);border:1px solid var(--border-strong);border-radius:2px;color:var(--muted);">${safeCode}</span>`;
  }

  const severity = (score) => {
    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  const riskColor = (score) => {
    if (score >= 70) return 'var(--primary)';
    if (score >= 40) return 'var(--medium)';
    return 'var(--low)';
  };

  const timeAgo = (timestamp) => {
    if (!timestamp) return '—';
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return '00:00:00';
    return new Date(timestamp).toLocaleTimeString('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'UTC'
    });
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return '—';
    return new Date(timestamp).toLocaleString('en-GB', {
      day: '2-digit',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit',
      timeZone: 'UTC'
    }) + ' UTC';
  };

  // State
  let events = [];
  let map;
  const markers = new Map();
  let highestEventId = 0;
  let page = 1;
  const pageSize = 10;
  let selectedEvent = null;
  let lastFocus = null;
  let blockedIpsSet = new Set();

  async function refreshBlockedIps() {
    try {
      const res = await fetch('/api/firewall/blocked');
      if (res.ok) {
        const list = await res.json();
        blockedIpsSet = new Set(list.map((item) => item.ip_address));
      }
    } catch (err) {
      console.warn('[HoneyTrack] Could not load firewall blacklist:', err);
    }
  }

  function normalizeEvent(e) {
    let ts = Date.now();
    if (e.timestamp) {
      const parsed = new Date(e.timestamp.endsWith('Z') ? e.timestamp : e.timestamp + 'Z');
      ts = isNaN(parsed.getTime()) ? new Date(e.timestamp).getTime() : parsed.getTime();
    }
    const country = e.country || 'Unknown';
    const city = e.city || 'Unknown';
    const flag = getCountryCode(country);
    const risk = typeof e.risk_score === 'number' ? Math.round(e.risk_score) : 45;

    return {
      id: Number(e.id),
      ip: e.source_ip || e.ip || '0.0.0.0',
      service: (e.service || 'SSH').toUpperCase(),
      country,
      city,
      flag,
      isp: e.isp || (e.is_tor ? 'Tor Exit Node' : 'Internet Service Provider'),
      lat: typeof e.latitude === 'number' ? e.latitude : (typeof e.lat === 'number' ? e.lat : 20),
      lng: typeof e.longitude === 'number' ? e.longitude : (typeof e.lon === 'number' ? e.lon : 0),
      type: e.attack_type || 'intrusion_attempt',
      risk,
      timestamp: ts,
      username: e.username,
      password: e.password,
      command: e.command,
      user_agent: e.user_agent,
      is_tor: !!e.is_tor
    };
  }

  function animateNumber(element, value, initial = false) {
    if (!element) return;
    const numValue = Number(value) || 0;
    const from = initial ? 0 : Number(element.dataset.value || 0);
    element.dataset.value = numValue;

    if (reduceMotion) {
      element.textContent = numValue.toLocaleString();
      return;
    }

    const start = performance.now();
    const duration = initial ? 600 : 350;

    function frame(t) {
      const progress = Math.min(1, (t - start) / duration);
      element.textContent = Math.round(from + (numValue - from) * (1 - Math.pow(1 - progress, 3))).toLocaleString();
      if (progress < 1) requestAnimationFrame(frame);
    }

    requestAnimationFrame(frame);
    if (!initial) {
      element.classList.remove('stat-flash');
      void element.offsetWidth;
      element.classList.add('stat-flash');
    }
  }

  function updateStatsDisplay(statsData, initial = false) {
    if (statsData) {
      animateNumber($('#total-attacks'), statsData.total_attacks, initial);
      animateNumber($('#unique-ips'), statsData.unique_ips, initial);
      animateNumber($('#countries'), statsData.unique_countries, initial);

      if (statsData.latest_attack) {
        const la = statsData.latest_attack;
        const locText = `${la.city || 'Unknown'}, ${la.country || 'Global'}`;
        if ($('#last-location')) $('#last-location').textContent = locText;
        let ts = Date.now();
        if (la.timestamp) {
          const parsed = new Date(la.timestamp.endsWith('Z') ? la.timestamp : la.timestamp + 'Z');
          ts = isNaN(parsed.getTime()) ? new Date(la.timestamp).getTime() : parsed.getTime();
        }
        if ($('#last-time')) $('#last-time').textContent = `${timeAgo(ts)} · ${formatTime(ts)} UTC`;
      } else {
        if ($('#last-location')) $('#last-location').textContent = '—';
        if ($('#last-time')) $('#last-time').textContent = 'Waiting for decoy interactions';
      }
    } else if (events.length > 0) {
      const uniqueIps = new Set(events.map((e) => e.ip)).size;
      const uniqueCountries = new Set(events.map((e) => e.country)).size;
      animateNumber($('#total-attacks'), events.length, initial);
      animateNumber($('#unique-ips'), uniqueIps, initial);
      animateNumber($('#countries'), uniqueCountries, initial);

      const latest = events[0];
      if ($('#last-location')) $('#last-location').textContent = `${latest.city}, ${latest.country}`;
      if ($('#last-time')) $('#last-time').textContent = `${timeAgo(latest.timestamp)} · ${formatTime(latest.timestamp)} UTC`;
    } else {
      animateNumber($('#total-attacks'), 0, initial);
      animateNumber($('#unique-ips'), 0, initial);
      animateNumber($('#countries'), 0, initial);
      if ($('#last-location')) $('#last-location').textContent = '—';
      if ($('#last-time')) $('#last-time').textContent = 'Waiting for decoy interactions';
    }
  }

  function initMap() {
    if (!window.L) {
      $('#attack-map').textContent = 'Map service offline. Live attack events remain visible in the feed.';
      return;
    }

    map = window.L.map('attack-map', {
      scrollWheelZoom: false,
      zoomControl: true,
      worldCopyJump: true
    }).setView([20, 10], 2);

    const carto = window.L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
      subdomains: 'abcd',
      maxZoom: 18
    }).addTo(map);

    // Fallback if CARTO tiles fail
    const tileProbe = new Image();
    tileProbe.crossOrigin = 'anonymous';
    tileProbe.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = canvas.height = 256;
        const context = canvas.getContext('2d');
        context.drawImage(tileProbe, 0, 0);
        const pixels = context.getImageData(0, 0, 256, 256).data;
        const samples = new Set();
        for (let i = 0; i < pixels.length; i += 64) samples.add(`${pixels[i]},${pixels[i+1]},${pixels[i+2]}`);
        if (samples.size < 30) {
          map.removeLayer(carto);
          window.L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
            attribution: 'Tiles &copy; Esri',
            maxZoom: 16
          }).addTo(map);
        }
      } catch (_) {}
    };
    tileProbe.src = 'https://a.basemaps.cartocdn.com/dark_all/2/2/1.png';

    // Plot initial markers
    events.slice(0, 35).reverse().forEach((e) => addMarker(e, false));
  }

  function addMarker(event, isNew) {
    if (!map || typeof event.lat !== 'number' || typeof event.lng !== 'number') return;
    if (event.lat === 0 && event.lng === 0) return;

    // Remove existing marker for this event if re-adding
    if (markers.has(event.id)) {
      map.removeLayer(markers.get(event.id));
    }

    const size = Math.round(10 + event.risk / 11);
    const color = riskColor(event.risk);
    const icon = window.L.divIcon({
      className: '',
      html: `<div class="attack-marker ${isNew ? 'new' : ''}" style="width:${size}px;height:${size}px;background:${color}"></div>`,
      iconSize: [size, size],
      iconAnchor: [size / 2, size / 2]
    });

    // Add slight jitter for duplicate coords
    const jitterLat = event.lat + (Math.random() - 0.5) * 0.8;
    const jitterLng = event.lng + (Math.random() - 0.5) * 0.8;

    const marker = window.L.marker([jitterLat, jitterLng], {
      icon,
      alt: `Attack from ${event.city}, ${event.country}`
    }).addTo(map);

    marker.bindPopup(`
      <div class="popup-ip">${escapeHtml(event.ip)} ${event.is_tor ? '<span class="tor-badge">TOR</span>' : ''}</div>
      <div><strong>${escapeHtml(event.city)}, ${escapeHtml(event.country)}</strong></div>
      <div style="font-family:var(--font-mono);font-size:10px;color:var(--low);margin:2px 0;">Coords: ${typeof event.lat === 'number' ? event.lat.toFixed(2) : 0}, ${typeof event.lng === 'number' ? event.lng.toFixed(2) : 0}</div>
      <div>ISP: ${escapeHtml(event.isp)}</div>
      <div>Service: <strong style="color:var(--foreground)">${escapeHtml(event.service)}</strong> · ${escapeHtml(event.type)}</div>
      <div class="popup-risk" style="color:${color};font-weight:600;margin-top:4px;">Risk: ${event.risk} / 100 (${severity(event.risk)})</div>
    `);

    marker.on('click', () => openPanel(event));
    markers.set(event.id, marker);

    if (markers.size > 30) {
      const oldest = markers.keys().next().value;
      map.removeLayer(markers.get(oldest));
      markers.delete(oldest);
    }
  }

  function feedMarkup(event, isNew = false) {
    const isBlocked = blockedIpsSet.has(event.ip);
    return `
      <button class="feed-item ${isNew ? 'new' : ''}" type="button" data-event-id="${event.id}" aria-label="View details for ${escapeHtml(event.ip)}">
        <span class="feed-top">
          <span class="feed-identity">
            ${flagImage(event.flag)}
            <span class="feed-ip">${escapeHtml(event.ip)}</span>
            ${isBlocked ? '<span class="blocked-badge">BLOCKED</span>' : ''}
          </span>
          <span class="feed-time" data-time="${event.timestamp}">${timeAgo(event.timestamp)}</span>
        </span>
        <span class="feed-bottom">
          <span class="service-badge">${escapeHtml(event.service)}</span>
          <span class="attack-tag">${escapeHtml(event.type)}</span>
          ${event.is_tor ? '<span class="service-badge" style="color:var(--primary);border-color:var(--primary-glow)">TOR</span>' : ''}
        </span>
      </button>
    `;
  }

  function renderFeed() {
    const listEl = $('#feed-list');
    if (!listEl) return;
    if (events.length === 0) {
      listEl.innerHTML = '<p class="profile-empty" style="padding:24px;text-align:center;">Listening for active intrusions...</p>';
      return;
    }
    listEl.innerHTML = events.slice(0, 35).map((e) => feedMarkup(e)).join('');
  }

  function renderTable() {
    const query = ($('#event-search')?.value || '').trim().toLowerCase();
    const serviceFilter = $('#filter-service')?.value || 'ALL';
    const riskFilter = $('#filter-risk')?.value || 'ALL';
    const torFilter = $('#filter-tor')?.value || 'ALL';

    const filtered = events.filter((e) => {
      // 1. Text Search query
      if (query) {
        const hay = `${e.ip} ${e.country} ${e.city} ${e.isp || ''} ${e.service} ${e.type} ${e.risk} ${e.username || ''} ${e.command || ''} ${e.user_agent || ''}`.toLowerCase();
        if (!hay.includes(query)) return false;
      }

      // 2. Service filter
      if (serviceFilter !== 'ALL' && e.service !== serviceFilter) return false;

      // 3. Risk filter
      if (riskFilter !== 'ALL') {
        if (riskFilter === '70' && e.risk < 70) return false;
        if (riskFilter === '40' && (e.risk < 40 || e.risk >= 70)) return false;
        if (riskFilter === 'LOW' && e.risk >= 40) return false;
      }

      // 4. Tor filter
      if (torFilter === 'TOR' && !e.is_tor) return false;
      if (torFilter === 'DIRECT' && e.is_tor) return false;

      return true;
    });

    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    page = Math.min(page, totalPages);
    const subset = filtered.slice((page - 1) * pageSize, page * pageSize);

    const rowsEl = $('#event-rows');
    if (!rowsEl) return;

    if (subset.length === 0) {
      if (events.length === 0) {
        rowsEl.innerHTML = '<tr><td class="empty-row" colspan="9" style="padding:32px 16px;color:var(--muted);"><span style="color:var(--low);font-weight:600;">● ALL SENSORS LISTENING</span> — No live attacks detected yet. Real-world adversary probes against SSH (2222), HTTP (8080), or FTP (2121) will appear here instantly.</td></tr>';
      } else {
        rowsEl.innerHTML = '<tr><td class="empty-row" colspan="9">No matching events found for active filters</td></tr>';
      }
    } else {
      rowsEl.innerHTML = subset.map((e) => {
        // Payload or credentials
        let payloadContent = '<span style="color:var(--muted-deep);">—</span>';
        if (e.command) {
          payloadContent = `<span class="payload-text payload-cmd" title="${escapeHtml(e.command)}">&gt; ${escapeHtml(e.command)}</span>`;
        } else if (e.username || e.password) {
          payloadContent = `<span class="payload-text" title="${escapeHtml(e.username || '-')}:${escapeHtml(e.password || '-')}">${escapeHtml(e.username || '-')}:${escapeHtml(e.password || '-')}</span>`;
        } else if (e.user_agent) {
          payloadContent = `<span class="payload-text" title="${escapeHtml(e.user_agent)}">UA: ${escapeHtml(e.user_agent)}</span>`;
        }

        const coordsStr = (typeof e.lat === 'number' && typeof e.lng === 'number') 
          ? `${e.lat.toFixed(2)}, ${e.lng.toFixed(2)}` 
          : 'N/A';

        return `
        <tr tabindex="0" role="button" aria-label="View details for ${escapeHtml(e.ip)}" data-event-id="${e.id}">
          <td class="time-cell">${formatTime(e.timestamp)}</td>
          <td class="mono">
            ${escapeHtml(e.ip)}
            ${e.is_tor ? '<span class="tor-badge">TOR</span>' : ''}
            ${blockedIpsSet.has(e.ip) ? '<span class="blocked-badge">BLOCKED</span>' : ''}
          </td>
          <td><span class="country-cell">${flagImage(e.flag)}${escapeHtml(e.city)}, ${escapeHtml(e.country)}</span></td>
          <td><span class="coords-mono">${coordsStr}</span></td>
          <td><span class="isp-text" title="${escapeHtml(e.isp)}">${escapeHtml(e.isp)}</span></td>
          <td><span class="service-badge">${escapeHtml(e.service)}</span></td>
          <td>${escapeHtml(e.type)}</td>
          <td>${payloadContent}</td>
          <td>
            <span class="risk-cell" style="--risk-color:${riskColor(e.risk)}">
              ${e.risk}
              <span class="risk-track">
                <span class="risk-fill" style="width:${e.risk}%"></span>
              </span>
            </span>
          </td>
        </tr>
      `;
      }).join('');
    }

    const paginationStatus = $('#pagination-status');
    if (paginationStatus) {
      paginationStatus.textContent = filtered.length
        ? `SHOWING ${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, filtered.length)} OF ${filtered.length} EVENTS`
        : '0 EVENTS';
    }

    const pageNumber = $('#page-number');
    if (pageNumber) pageNumber.textContent = `${page} / ${totalPages}`;

    const prevBtn = $('#previous-page');
    if (prevBtn) prevBtn.disabled = page === 1;

    const nextBtn = $('#next-page');
    if (nextBtn) nextBtn.disabled = page >= totalPages;
  }

  function panelMarkup(e) {
    const isBlocked = blockedIpsSet.has(e.ip);
    // Find all attempts by this same IP in recent history
    const sameIpEvents = events.filter((item) => item.ip === e.ip);
    const totalAttempts = sameIpEvents.length;

    // Collect credentials
    const credentialsSet = new Set();
    sameIpEvents.forEach((ev) => {
      if (ev.username || ev.password) {
        credentialsSet.add(`${ev.username || 'unknown'}:${ev.password || '******'}`);
      }
    });
    const credentialsList = Array.from(credentialsSet);

    // Collect commands
    const commandsSet = new Set();
    sameIpEvents.forEach((ev) => {
      if (ev.command) commandsSet.add(ev.command);
    });
    const commandsList = Array.from(commandsSet);

    // First and last seen
    const timestamps = sameIpEvents.map((ev) => ev.timestamp);
    const firstSeen = Math.min(...timestamps);
    const lastSeen = Math.max(...timestamps);

    const credentialsHtml = credentialsList.length
      ? `<div class="credential-list">${credentialsList.map((c) => `<span class="credential">${escapeHtml(c)}</span>`).join('')}</div>`
      : '<p class="profile-empty">No credentials captured for this host</p>';

    const commandsHtml = commandsList.length
      ? `<div class="terminal">${commandsList.map((c) => `<div class="terminal-line">${escapeHtml(c)}</div>`).join('')}</div>`
      : '<p class="profile-empty">No commands executed</p>';

    return `
      <h3 class="profile-ip">${escapeHtml(e.ip)}</h3>
      <p class="profile-location">${flagImage(e.flag)} ${escapeHtml(e.city)}, ${escapeHtml(e.country)}</p>

      <div class="profile-gauge-area">
        <div class="risk-gauge" role="meter" aria-label="Risk score" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${e.risk}" style="--gauge-color:${riskColor(e.risk)};--gauge-value:${e.risk}%">
          <div class="risk-gauge-inner">
            <strong>${e.risk}</strong>
            <small>/ 100</small>
          </div>
        </div>
        <div>
          <span class="gauge-label">RISK ASSESSMENT</span>
          <p class="gauge-severity" style="color:${riskColor(e.risk)}">${severity(e.risk)} RISK</p>
        </div>
      </div>

      <section class="profile-section">
        <h3>SOURCE INFORMATION</h3>
        <div class="profile-grid">
          <div class="profile-field">
            <span>Country</span>
            <strong>${escapeHtml(e.country)}</strong>
          </div>
          <div class="profile-field">
            <span>City</span>
            <strong>${escapeHtml(e.city)}</strong>
          </div>
          <div class="profile-field">
            <span>Coordinates (Lat/Lon)</span>
            <strong class="mono" style="color:var(--low);">${typeof e.lat === 'number' ? e.lat.toFixed(4) : 'N/A'}, ${typeof e.lng === 'number' ? e.lng.toFixed(4) : 'N/A'}</strong>
          </div>
          <div class="profile-field">
            <span>ISP / Network</span>
            <strong>${escapeHtml(e.isp)}</strong>
          </div>
          <div class="profile-field">
            <span>Anonymity Profile</span>
            <strong>${e.is_tor ? '<span class="tor-badge" style="margin-left:0;">TOR EXIT NODE (CONFIRMED)</span>' : '<span style="color:var(--muted);">DIRECT PUBLIC IP</span>'}</strong>
          </div>
          <div class="profile-field">
            <span>Recorded Hits</span>
            <strong>${totalAttempts} attempt${totalAttempts > 1 ? 's' : ''}</strong>
          </div>
          <div class="profile-field">
            <span>First Detected</span>
            <strong class="mono">${formatDate(firstSeen)}</strong>
          </div>
          <div class="profile-field">
            <span>Last Detected</span>
            <strong class="mono">${formatDate(lastSeen)}</strong>
          </div>
        </div>
      </section>

      <section class="profile-section">
        <h3>CREDENTIALS TRIED</h3>
        ${credentialsHtml}
      </section>

      <section class="profile-section">
        <h3>COMMANDS EXECUTED</h3>
        ${commandsHtml}
      </section>

      <section class="profile-section">
        <h3>ATTACK CLASSIFICATION</h3>
        <p class="classification">
          ${escapeHtml(e.type)} 
          <span class="service-badge">${escapeHtml(e.service)}</span>
          ${e.is_tor ? '<span class="service-badge" style="color:var(--primary);border-color:var(--primary-glow);margin-left:4px;">TOR EXIT NODE</span>' : ''}
        </p>
      </section>

      <section class="profile-section">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <h3 style="margin:0;">ACTIVE FIREWALL MITIGATION</h3>
          <span class="firewall-badge ${isBlocked ? 'blocked' : 'active'}" id="drawer-firewall-badge">
            ${isBlocked ? 'BLOCKED (PACKETS DROPPED)' : 'UNFILTERED (ACTIVE)'}
          </span>
        </div>
        <p style="font-size:11px; color:var(--muted); margin:0 0 12px 0;">
          ${isBlocked 
            ? 'Adversary IP is actively blacklisted. Honeypot decoy listeners will reject incoming connections immediately.' 
            : 'Adversary activity detected. Blacklist this IP in active defense or deploy host firewall rules to prevent deeper intrusion.'}
        </p>
        <button type="button" class="btn-firewall-toggle ${isBlocked ? 'btn-unblock' : 'btn-block'}" id="btn-firewall-toggle-ip" data-ip="${escapeHtml(e.ip)}" data-risk="${e.risk}" data-country="${escapeHtml(e.country)}">
          ${isBlocked ? 'UNBLOCK IP (RESTORE ACCESS)' : 'BLOCK IP (FIREWALL DROP)'}
        </button>

        ${commandsList.length > 0 ? `
        <button type="button" class="btn-fed-action primary" id="btn-drawer-watch-replay" data-ip="${escapeHtml(e.ip)}" style="width:100%;margin-top:10px;display:flex;align-items:center;justify-content:center;gap:8px;padding:9px 14px;background:#22c55e22;border:1px solid #22c55e;color:#22c55e;font-size:11px;font-family:var(--font-mono);font-weight:700;border-radius:4px;cursor:pointer;">
          ▶ WATCH TERMINAL REPLAY FOR THIS IP
        </button>
        ` : `
        <div style="margin-top:10px;padding:8px 12px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:4px;font-size:10.5px;color:var(--muted);font-family:var(--font-mono);text-align:center;font-style:italic;">
          This attacker has not executed any commands
        </div>
        `}

        <div class="firewall-commands-box">
          <div class="firewall-cmd-header">
            <span>RECOMMENDED HOST FIREWALL RULE</span>
            <button type="button" class="btn-copy-cmd" id="btn-copy-firewall-cmd">COPY</button>
          </div>
          <pre class="firewall-code" id="firewall-cmd-code">sudo ufw insert 1 deny from ${escapeHtml(e.ip)} to any comment 'HoneyTrack Auto-Block'</pre>
        </div>
      </section>
    `;
  }

  async function openPanel(event) {
    selectedEvent = event;
    lastFocus = document.activeElement;

    // Synchronize latest firewall state for this IP
    try {
      const res = await fetch(`/api/firewall/status/${encodeURIComponent(event.ip)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.is_blocked) {
          blockedIpsSet.add(event.ip);
        } else {
          blockedIpsSet.delete(event.ip);
        }
      }
    } catch (_) {}

    $('#panel-body').innerHTML = panelMarkup(event);
    const panel = $('#detail-panel');
    const backdrop = $('#panel-backdrop');
    backdrop.hidden = false;

    requestAnimationFrame(() => {
      panel.classList.add('open');
      backdrop.classList.add('open');
    });

    panel.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    $('#panel-close').focus();
  }

  function closePanel() {
    const panel = $('#detail-panel');
    const backdrop = $('#panel-backdrop');
    panel.classList.remove('open');
    backdrop.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';

    window.setTimeout(() => {
      if (!panel.classList.contains('open')) backdrop.hidden = true;
    }, reduceMotion ? 0 : 320);

    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
    selectedEvent = null;
  }

  // Event handlers
  $('#feed-list')?.addEventListener('click', (e) => {
    const row = e.target.closest('[data-event-id]');
    if (row) {
      const ev = events.find((item) => item.id === Number(row.dataset.eventId));
      if (ev) openPanel(ev);
    }
  });

  $('#event-rows')?.addEventListener('click', (e) => {
    const row = e.target.closest('[data-event-id]');
    if (row) {
      const ev = events.find((item) => item.id === Number(row.dataset.eventId));
      if (ev) openPanel(ev);
    }
  });

  $('#event-rows')?.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[data-event-id]')) {
      e.preventDefault();
      e.target.click();
    }
  });

  $('#panel-close')?.addEventListener('click', closePanel);
  $('#panel-backdrop')?.addEventListener('click', closePanel);

  // Firewall Mitigation Drawer Action Handlers
  $('#panel-body')?.addEventListener('click', async (e) => {
    const toggleBtn = e.target.closest('#btn-firewall-toggle-ip');
    if (toggleBtn) {
      const ip = toggleBtn.dataset.ip;
      const risk = Number(toggleBtn.dataset.risk || 0);
      const country = toggleBtn.dataset.country || 'Unknown';
      const isCurrentlyBlocked = blockedIpsSet.has(ip);

      toggleBtn.disabled = true;
      toggleBtn.textContent = isCurrentlyBlocked ? 'REMOVING BLOCK...' : 'APPLYING DROP RULE...';

      try {
        const endpoint = isCurrentlyBlocked ? '/api/firewall/unblock' : '/api/firewall/block';
        const bodyData = isCurrentlyBlocked ? { ip } : { ip, risk_score: risk, country, reason: 'Operator Console Manual Blacklist' };
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyData)
        });
        const data = await res.json();

        if (res.ok && data.success) {
          if (isCurrentlyBlocked) {
            blockedIpsSet.delete(ip);
          } else {
            blockedIpsSet.add(ip);
          }
          if (selectedEvent && selectedEvent.ip === ip) {
            $('#panel-body').innerHTML = panelMarkup(selectedEvent);
          }
          renderFeed();
          renderTable();
        } else {
          alert('Firewall mitigation action failed: ' + (data.message || data.error));
          toggleBtn.disabled = false;
        }
      } catch (err) {
        alert('Network error: ' + err.message);
        toggleBtn.disabled = false;
      }
      return;
    }

    const replayBtn = e.target.closest('#btn-drawer-watch-replay');
    if (replayBtn) {
      const ip = replayBtn.dataset.ip;
      closePanel();
      try {
        const res = await fetch(`/api/federation/search?ip=${encodeURIComponent(ip)}`).then((r) => r.json());
        if (res.session_id) {
          window.openTerminalReplayModal(res.session_id);
        } else {
          window.openTerminalReplayModal();
        }
      } catch (_) {
        window.openTerminalReplayModal();
      }
      return;
    }

    const copyBtn = e.target.closest('#btn-copy-firewall-cmd');
    if (copyBtn) {
      const codeEl = $('#firewall-cmd-code');
      if (codeEl) {
        navigator.clipboard.writeText(codeEl.textContent.trim()).then(() => {
          copyBtn.textContent = 'COPIED!';
          setTimeout(() => { copyBtn.textContent = 'COPY'; }, 2000);
        });
      }
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (selectedEvent) closePanel();
      closeEmailModal();
    }
  });

  function getFilterQuery() {
    const srv = $('#filter-service')?.value || 'ALL';
    const risk = $('#filter-risk')?.value || 'ALL';
    const tor = $('#filter-tor')?.value || 'ALL';
    const search = ($('#event-search')?.value || '').trim();

    const params = new URLSearchParams();
    if (srv !== 'ALL') params.append('service', srv);
    if (risk !== 'ALL') {
      if (risk === 'LOW') params.append('max_risk', '39');
      else params.append('min_risk', risk);
    }
    if (tor === 'TOR') params.append('is_tor', 'true');
    if (tor === 'DIRECT') params.append('is_tor', 'false');
    if (search) params.append('search', search);
    return params;
  }

  function exportPdfReport() {
    const params = getFilterQuery();
    window.location.href = `/api/reports/pdf?${params.toString()}`;
  }

  $('#btn-top-pdf')?.addEventListener('click', (e) => {
    e.preventDefault();
    exportPdfReport();
  });

  // Email Alerts & Diagnostics Modal
  async function openEmailModal() {
    const modal = $('#email-modal');
    const backdrop = $('#email-modal-backdrop');
    if (!modal || !backdrop) return;
    backdrop.hidden = false;
    modal.hidden = false;
    requestAnimationFrame(() => {
      modal.classList.add('open');
      backdrop.classList.add('open');
    });

    const resBox = $('#email-test-result');
    if (resBox) resBox.hidden = true;

    try {
      const res = await fetch('/api/alerts/status');
      if (res.ok) {
        const data = await res.json();
        if ($('#diag-smtp-server')) {
          $('#diag-smtp-server').textContent = `${data.smtp_host}:${data.smtp_port} (TLS)`;
        }
        if ($('#diag-smtp-account')) {
          $('#diag-smtp-account').textContent = data.smtp_username || 'Not configured';
        }
        if ($('#diag-smtp-threshold')) {
          $('#diag-smtp-threshold').innerHTML = `Risk &ge; ${data.threshold} or Tor Exit Node`;
        }
        if ($('#diag-smtp-cooldown')) {
          $('#diag-smtp-cooldown').textContent = `${data.cooldown_seconds}s per-IP`;
        }
        if ($('#diag-recipient-email') && data.recipient && !$('#diag-recipient-email').value) {
          $('#diag-recipient-email').value = data.recipient;
        }
      }
    } catch (e) {
      console.warn('[HoneyTrack] Could not fetch alert status:', e);
    }
  }

  function closeEmailModal() {
    const modal = $('#email-modal');
    const backdrop = $('#email-modal-backdrop');
    if (!modal || !backdrop) return;
    modal.classList.remove('open');
    backdrop.classList.remove('open');
    window.setTimeout(() => {
      if (!modal.classList.contains('open')) {
        modal.hidden = true;
        backdrop.hidden = true;
      }
    }, 260);
  }

  async function sendTestEmailAlert() {
    const emailInput = $('#diag-recipient-email');
    const sendBtn = $('#btn-send-test-email');
    const spinner = $('#email-spinner');
    const label = $('#btn-email-text');
    const resultBox = $('#email-test-result');
    const badge = $('#result-status-badge');
    const text = $('#result-status-text');

    const recipient = (emailInput?.value || '').trim();
    if (!recipient) {
      alert('Please enter a valid recipient email address.');
      emailInput?.focus();
      return;
    }

    sendBtn.disabled = true;
    if (spinner) spinner.hidden = false;
    if (label) label.textContent = 'CONNECTING SMTP...';
    if (resultBox) resultBox.hidden = true;

    try {
      const res = await fetch('/api/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: recipient })
      });
      const data = await res.json();

      resultBox.hidden = false;
      if (res.ok && data.success) {
        resultBox.className = 'email-test-result success';
        badge.textContent = 'DELIVERED (HTTP 200)';
        text.textContent = data.message || `Test threat intelligence alert successfully dispatched to ${recipient}.`;
      } else {
        resultBox.className = 'email-test-result error';
        badge.textContent = 'SMTP ERROR';
        text.textContent = data.message || data.error || 'Failed to authenticate or connect with SMTP server.';
      }
    } catch (err) {
      resultBox.hidden = false;
      resultBox.className = 'email-test-result error';
      badge.textContent = 'NETWORK FAULT';
      text.textContent = `Request failed: ${err.message}`;
    } finally {
      sendBtn.disabled = false;
      if (spinner) spinner.hidden = true;
      if (label) label.textContent = 'SEND TEST ALERT';
    }
  }

  $('#btn-email-modal-toggle')?.addEventListener('click', openEmailModal);
  $('#btn-close-email-modal')?.addEventListener('click', closeEmailModal);
  $('#email-modal-backdrop')?.addEventListener('click', closeEmailModal);
  $('#btn-send-test-email')?.addEventListener('click', sendTestEmailAlert);

  $('#btn-table-pdf')?.addEventListener('click', () => {
    exportPdfReport();
  });

  $('#filter-service')?.addEventListener('change', () => {
    page = 1;
    renderTable();
  });

  $('#filter-risk')?.addEventListener('change', () => {
    page = 1;
    renderTable();
  });

  $('#filter-tor')?.addEventListener('change', () => {
    page = 1;
    renderTable();
  });

  $('#btn-reset-filters')?.addEventListener('click', () => {
    if ($('#filter-service')) $('#filter-service').value = 'ALL';
    if ($('#filter-risk')) $('#filter-risk').value = 'ALL';
    if ($('#filter-tor')) $('#filter-tor').value = 'ALL';
    if ($('#event-search')) $('#event-search').value = '';
    page = 1;
    renderTable();
  });

  $('#btn-clear-live')?.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to clear live production attacks and restart counts from 0?')) return;
    try {
      const res = await fetch('/api/admin/clear-live', { method: 'POST' });
      if (res.ok) {
        events = [];
        highestEventId = 0;
        markers.forEach((m) => m.remove());
        markers.clear();
        const statsRes = await fetch('/api/stats').then((r) => r.json());
        updateStatsDisplay(statsRes, false);
        renderFeed();
        renderTable();
      }
    } catch (err) {
      console.error('[HoneyTrack] Error clearing live events:', err);
    }
  });

  $('#event-search')?.addEventListener('input', () => {
    page = 1;
    renderTable();
  });

  $('#previous-page')?.addEventListener('click', () => {
    if (page > 1) {
      page--;
      renderTable();
    }
  });

  $('#next-page')?.addEventListener('click', () => {
    page++;
    renderTable();
  });

  // Backend API fetching
  async function loadInitialData() {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        fetch('/api/events?limit=300').then((r) => r.json()),
        fetch('/api/stats').then((r) => r.json()),
        refreshBlockedIps()
      ]);

      if (Array.isArray(eventsRes) && eventsRes.length > 0) {
        events = eventsRes.map(normalizeEvent);
        highestEventId = Math.max(...events.map((e) => e.id));
      }

      updateStatsDisplay(statsRes, true);
      initMap();
      renderFeed();
      renderTable();
    } catch (err) {
      console.error('[HoneyTrack] Error loading initial telemetry:', err);
    }
  }

  async function pollLatestEvents() {
    try {
      const url = highestEventId > 0
        ? `/api/events/latest?since_id=${highestEventId}`
        : '/api/events?limit=20';

      const res = await fetch(url);
      if (!res.ok) return;
      const newItems = await res.json();

      if (Array.isArray(newItems) && newItems.length > 0) {
        const normalized = newItems.map(normalizeEvent);
        normalized.sort((a, b) => b.id - a.id);

        for (const ev of normalized) {
          if (!events.some((e) => e.id === ev.id)) {
            events.unshift(ev);
            addMarker(ev, true);
            if (ev.id > highestEventId) highestEventId = ev.id;
          }
        }
        if (events.length > 200) {
          events.length = 200;
        }

        renderFeed();
        renderTable();

        // Refresh stats after new events
        const statsRes = await fetch('/api/stats').then((r) => r.json());
        updateStatsDisplay(statsRes, false);
      }
    } catch (err) {
      console.warn('[HoneyTrack] Polling error:', err);
    }
  }

  // Periodic relative time tick
  window.setInterval(() => {
    document.querySelectorAll('[data-time]').forEach((el) => {
      el.textContent = timeAgo(Number(el.dataset.time));
    });
    if (events[0]) {
      $('#last-time').textContent = `${timeAgo(events[0].timestamp)} · ${formatTime(events[0].timestamp)} UTC`;
    }
  }, 1000);

  // Poll backend every 2.5 seconds
  window.setInterval(pollLatestEvents, 2500);

  // Poll stats and firewall blacklist every 15 seconds to ensure synchronization
  window.setInterval(async () => {
    try {
      const [statsRes] = await Promise.all([
        fetch('/api/stats').then((r) => r.json()),
        refreshBlockedIps()
      ]);
      updateStatsDisplay(statsRes, false);
      renderFeed();
      renderTable();
    } catch (_) {}
  }, 15000);

  // ─────────────────────────────────────────────────────────────
  // Terminal Session Replayer (v1.2)
  // ─────────────────────────────────────────────────────────────
  let replaySessions = [];
  let currentReplaySession = null;
  let replayEvents = [];
  let replayIndex = 0;
  let replayTimeout = null;
  let replaySpeed = 1;
  let replayIsPlaying = false;
  let replayElapsedSec = 0;

  async function loadReplaySessionsList(preferredSessionId = null) {
    try {
      const res = await fetch('/api/sessions?limit=50').then((r) => r.json());
      if (res.status === 'success' && Array.isArray(res.sessions)) {
        replaySessions = res.sessions;
        const select = $('#replay-session-select');
        if (!select) return;
        select.innerHTML = '';
        if (replaySessions.length === 0) {
          select.innerHTML = '<option value="">No recorded sessions available</option>';
          return;
        }
        replaySessions.forEach((s) => {
          const opt = document.createElement('option');
          opt.value = s.session_id;
          opt.textContent = `${s.source_ip} · ${s.service} (${s.username || 'unknown'}) · ${s.duration_seconds}s`;
          select.appendChild(opt);
        });

        const targetId = preferredSessionId || (replaySessions[0] ? replaySessions[0].session_id : null);
        if (targetId) {
          select.value = targetId;
          await selectReplaySession(targetId);
        }
      }
    } catch (e) {
      console.warn('[HoneyTrack] Error loading sessions list:', e);
    }
  }

  async function selectReplaySession(sessionId) {
    stopReplay();
    const termOut = $('#terminal-output');
    if (termOut) termOut.textContent = 'Loading recorded session stream...';
    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/replay`).then((r) => r.json());
      if (res.status === 'success' && res.session) {
        currentReplaySession = res.session;
        replayEvents = res.session.events || [];
        replayIndex = 0;
        replayElapsedSec = 0;

        $('#replay-meta-ip').textContent = `IP: ${currentReplaySession.source_ip}`;
        $('#replay-meta-user').textContent = `USER: ${currentReplaySession.username || 'unknown'}`;
        $('#replay-meta-cmds').textContent = `CMDS: ${currentReplaySession.commands_count || 0}`;
        updateReplayProgress();

        if (termOut) termOut.textContent = '';
        startReplay();
      }
    } catch (e) {
      if (termOut) termOut.textContent = 'Failed to load session recording.';
    }
  }

  function startReplay() {
    if (!currentReplaySession || replayEvents.length === 0) return;
    replayIsPlaying = true;
    const playBtn = $('#btn-replay-play');
    if (playBtn) playBtn.textContent = '❚❚ PAUSE';

    function scheduleNext() {
      if (!replayIsPlaying) return;
      if (replayIndex >= replayEvents.length) {
        replayIsPlaying = false;
        if (playBtn) playBtn.textContent = '▶ PLAY';
        return;
      }

      const evt = replayEvents[replayIndex];
      const targetOffset = evt[0];
      const nextDelay = Math.max(10, Math.floor(((targetOffset - replayElapsedSec) * 1000) / replaySpeed));

      replayTimeout = setTimeout(() => {
        if (!replayIsPlaying) return;
        const [offset, type, data] = replayEvents[replayIndex];
        replayElapsedSec = offset;
        const termOut = $('#terminal-output');
        const termScreen = $('#terminal-screen');
        if (termOut && data) {
          termOut.textContent += data;
          if (termScreen) termScreen.scrollTop = termScreen.scrollHeight;
        }
        updateReplayProgress();
        replayIndex++;
        scheduleNext();
      }, nextDelay);
    }

    scheduleNext();
  }

  function stopReplay() {
    replayIsPlaying = false;
    if (replayTimeout) {
      clearTimeout(replayTimeout);
      replayTimeout = null;
    }
    const playBtn = $('#btn-replay-play');
    if (playBtn) playBtn.textContent = '▶ PLAY';
  }

  function updateReplayProgress() {
    const totalSec = currentReplaySession ? currentReplaySession.duration_seconds || 1 : 1;
    const currentSec = Math.min(totalSec, replayElapsedSec);
    const pct = Math.min(100, Math.max(0, (currentSec / totalSec) * 100));
    const fill = $('#replay-timeline-fill');
    if (fill) fill.style.width = `${pct.toFixed(1)}%`;

    const timer = $('#replay-timer');
    if (timer) {
      const pad = (n) => String(Math.floor(n)).padStart(2, '0');
      timer.textContent = `${pad(currentSec / 60)}:${pad(currentSec % 60)} / ${pad(totalSec / 60)}:${pad(totalSec % 60)}`;
    }
  }

  function initReplayModal() {
    const btnToggle = $('#btn-replay-modal-toggle');
    const modal = $('#replay-modal');
    const backdrop = $('#replay-modal-backdrop');
    const btnClose = $('#btn-close-replay-modal');

    function openModal(sessionId = null) {
      if (modal) {
        modal.hidden = false;
        modal.style.display = 'flex';
      }
      if (backdrop) {
        backdrop.hidden = false;
        backdrop.style.display = 'block';
      }
      loadReplaySessionsList(sessionId);
    }

    function closeModal() {
      stopReplay();
      if (modal) {
        modal.hidden = true;
        modal.style.display = 'none';
      }
      if (backdrop) {
        backdrop.hidden = true;
        backdrop.style.display = 'none';
      }
    }

    btnToggle?.addEventListener('click', () => openModal());
    btnClose?.addEventListener('click', closeModal);
    backdrop?.addEventListener('click', closeModal);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.hidden) closeModal();
    });

    $('#replay-session-select')?.addEventListener('change', (e) => {
      if (e.target.value) selectReplaySession(e.target.value);
    });

    $('#btn-replay-play')?.addEventListener('click', () => {
      if (replayIsPlaying) {
        stopReplay();
      } else {
        if (replayIndex >= replayEvents.length) {
          replayIndex = 0;
          replayElapsedSec = 0;
          const termOut = $('#terminal-output');
          if (termOut) termOut.textContent = '';
        }
        startReplay();
      }
    });

    $('#btn-replay-restart')?.addEventListener('click', () => {
      stopReplay();
      replayIndex = 0;
      replayElapsedSec = 0;
      const termOut = $('#terminal-output');
      if (termOut) termOut.textContent = '';
      updateReplayProgress();
      startReplay();
    });

    document.querySelectorAll('.speed-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.speed-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        replaySpeed = Number(btn.dataset.speed) || 1;
      });
    });

    window.openTerminalReplayModal = openModal;
  }

  // ─────────────────────────────────────────────────────────────
  // Node Federation Controller (v2.0)
  // ─────────────────────────────────────────────────────────────
  function initFederationModal() {
    const btnToggle = $('#btn-fed-modal-toggle');
    const modal = $('#fed-modal');
    const backdrop = $('#fed-modal-backdrop');
    const btnClose = $('#btn-close-fed-modal');
    const statusNote = $('#fed-action-status');

    const searchInput = $('#fed-ip-search-input');
    const btnSearchIp = $('#btn-fed-search-ip');
    const searchResults = $('#fed-search-results');

    function parseTimestamp(ts) {
      if (!ts) return null;
      if (typeof ts === 'number') return ts;
      let str = String(ts).trim();
      if (!str.endsWith('Z') && !str.includes('+')) {
        str = str.replace(' ', 'T') + 'Z';
      }
      const parsed = new Date(str).getTime();
      return isNaN(parsed) ? new Date(ts).getTime() : parsed;
    }

    function openModal() {
      if (modal) {
        modal.hidden = false;
        modal.style.display = 'flex';
      }
      if (backdrop) {
        backdrop.hidden = false;
        backdrop.style.display = 'block';
      }
      if (statusNote) statusNote.textContent = '';
      loadFederationData();
    }

    function closeModal() {
      if (modal) {
        modal.hidden = true;
        modal.style.display = 'none';
      }
      if (backdrop) {
        backdrop.hidden = true;
        backdrop.style.display = 'none';
      }
    }

    window.honeytrackOpenFederationModal = openModal;

    async function loadFederationData() {
      try {
        const res = await fetch('/api/federation/nodes').then((r) => r.json());
        if (res.status === 'success') {
          if (res.local_node) {
            if ($('#fed-local-name')) $('#fed-local-name').textContent = res.local_node.node_name || 'HoneyTrack Primary Node';
            if ($('#fed-local-region')) $('#fed-local-region').textContent = `Region: ${res.local_node.region || 'Global'}`;
          }

          const nodes = res.nodes || [];
          const totalNodes = nodes.length;
          const onlineCount = nodes.filter((n) => n.status === 'online').length;
          const totalAttacksReported = nodes.reduce((sum, n) => sum + (n.attacks_reported || 0), 0);

          // Update Main Dashboard Federated Overview Bar
          const dashTotalEl = $('#dash-fed-total-count');
          const dashOnlineEl = $('#dash-fed-online-count');
          const dashAttacksEl = $('#dash-fed-reported-attacks');
          const dashPillsEl = $('#dash-fed-node-pills');

          if (dashTotalEl) dashTotalEl.textContent = `${totalNodes} Node${totalNodes === 1 ? '' : 's'} Connected`;
          if (dashOnlineEl) dashOnlineEl.textContent = `${onlineCount} Active Online`;
          if (dashAttacksEl) dashAttacksEl.textContent = `· ${totalAttacksReported} Remote Attacks Ingested`;
          if ($('#fed-modal-nodes-badge')) $('#fed-modal-nodes-badge').textContent = `${totalNodes} Node${totalNodes === 1 ? '' : 's'}`;

          if (dashPillsEl) {
            dashPillsEl.innerHTML = '';
            nodes.slice(0, 5).forEach((n) => {
              const pill = document.createElement('span');
              const isHub = n.is_hub;
              pill.className = `fed-role-badge ${isHub ? 'hub' : 'sensor'}`;
              pill.style.cssText = 'font-size:10.5px;padding:4px 10px;cursor:pointer;';
              pill.title = `${n.node_name} (${n.region}) - ${n.status.toUpperCase()} - ${n.attacks_reported || 0} attacks`;
              pill.innerHTML = `<span class="node-status-dot ${n.status === 'online' ? 'online' : 'offline'}" style="margin-right:4px;"></span> ${escapeHtml(n.node_name || n.node_id)}`;
              pill.addEventListener('click', openModal);
              dashPillsEl.appendChild(pill);
            });
            if (nodes.length > 5) {
              const morePill = document.createElement('span');
              morePill.className = 'fed-role-badge sensor';
              morePill.style.cssText = 'font-size:10.5px;padding:4px 8px;cursor:pointer;color:#38bdf8;';
              morePill.textContent = `+${nodes.length - 5} more`;
              morePill.addEventListener('click', openModal);
              dashPillsEl.appendChild(morePill);
            }
          }

          const tbody = $('#fed-nodes-tbody');
          if (!tbody) {
            console.warn('[HoneyTrack] #fed-nodes-tbody element not found in DOM.');
            return;
          }
          tbody.innerHTML = '';

          if (nodes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-row" style="text-align:center;padding:24px;color:#94a3b8;">No sensor nodes registered. Click "SEED GLOBAL SENSORS" above to connect demo sensors.</td></tr>';
            return;
          }

          nodes.forEach((n) => {
            try {
              const tr = document.createElement('tr');
              const isOnline = n.status === 'online';
              const statusClass = isOnline ? 'online' : 'offline';
              const roleClass = n.is_hub ? 'hub' : 'sensor';
              const roleText = n.is_hub ? 'HUB' : 'SENSOR';
              const localTag = n.is_local ? ' <span style="color:#38bdf8;font-size:9.5px;background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.3);padding:1px 5px;border-radius:3px;">[THIS HOST]</span>' : '';
              const deleteAction = n.is_local
                ? '<span style="color:#64748b;font-size:10px;font-weight:600;">PROTECTED</span>'
                : `<button type="button" class="btn-del-node" data-node-id="${escapeHtml(n.node_id)}" onclick="window.honeytrackRemoveNode('${escapeHtml(n.node_id)}')" style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;color:#ef4444;border-radius:4px;padding:4px 10px;font-size:10.5px;cursor:pointer;font-family:var(--font-mono);font-weight:700;transition:all 0.15s;">REMOVE</button>`;

              const hbTs = parseTimestamp(n.last_heartbeat);
              const hbText = hbTs ? timeAgo(hbTs) : 'just now';

              tr.innerHTML = `
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;"><strong>${escapeHtml(n.node_name || n.node_id)}</strong>${localTag}<div style="color:#64748b;font-size:10px;">${escapeHtml(n.node_id)}</div></td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;">${escapeHtml(n.region || 'Global')}</td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;"><span class="node-status-dot ${statusClass}"></span>${isOnline ? 'ONLINE' : 'OFFLINE'}</td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;">${n.attacks_reported || 0}</td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;">${hbText}</td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;color:#cbd5e1;"><span class="fed-role-badge ${roleClass}">${roleText}</span></td>
                <td style="padding:11px 14px;border-bottom:1px solid #0f172a;text-align:center;">${deleteAction}</td>
              `;
              tbody.appendChild(tr);
            } catch (rowErr) {
              console.error('[HoneyTrack] Error rendering row for node:', n, rowErr);
            }
          });
        }
      } catch (e) {
        console.warn('[HoneyTrack] Error loading federation nodes:', e);
      }
    }

    // Node deletion handler
    async function deleteNode(nid) {
      if (!nid) return;
      if (!confirm(`Are you sure you want to remove remote sensor node '${nid}'?`)) return;
      try {
        if (statusNote) statusNote.textContent = `Removing node '${nid}'...`;
        const res = await fetch(`/api/federation/nodes/${encodeURIComponent(nid)}`, { method: 'DELETE' }).then((r) => r.json());
        if (res.status === 'success') {
          if (statusNote) statusNote.textContent = `Node '${nid}' removed from roster.`;
          await loadFederationData();
        } else {
          alert(res.error || 'Failed to remove node.');
          if (statusNote) statusNote.textContent = res.error || 'Failed to remove node.';
        }
      } catch (err) {
        alert('Network error removing node.');
        if (statusNote) statusNote.textContent = 'Network error removing node.';
      }
    }

    window.honeytrackRemoveNode = deleteNode;

    $('#fed-nodes-tbody')?.addEventListener('click', async (e) => {
      const delBtn = e.target.closest('.btn-del-node');
      if (delBtn) {
        e.preventDefault();
        e.stopPropagation();
        const nid = delBtn.dataset.nodeId;
        await deleteNode(nid);
      }
    });

    // Cross-Node Attacker Search & Session Replay
    async function performIpSearch(queryIp = null) {
      const ip = (queryIp || searchInput?.value || '').trim();
      if (!ip) return;
      if (searchInput) searchInput.value = ip;
      if (searchResults) {
        searchResults.hidden = false;
        searchResults.innerHTML = '<p style="color:var(--muted);font-size:11px;font-family:var(--font-mono);padding:10px;">Searching cross-node threat intelligence...</p>';
      }

      try {
        const res = await fetch(`/api/federation/search?ip=${encodeURIComponent(ip)}`).then((r) => r.json());
        if (!res.found) {
          searchResults.innerHTML = `
            <div style="background:#0f172a;border:1px solid #334155;border-radius:6px;padding:12px;font-family:var(--font-mono);font-size:11.5px;color:#94a3b8;">
              <span style="color:#ef4444;font-weight:700;">● NO RECORDS FOUND</span> for <strong>${escapeHtml(ip)}</strong> across active federated sensors.
            </div>
          `;
          return;
        }

        const hasCommands = Boolean(res.has_commands && res.commands && res.commands.length > 0);

        const cmdHtml = hasCommands
          ? `<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px;">` + res.commands.map((c) => `<code style="background:#030712;padding:2px 7px;border-radius:3px;color:#22c55e;font-size:11px;">&gt; ${escapeHtml(c)}</code>`).join(' ') + `</div>`
          : '<div style="margin-top:6px;color:#f59e0b;font-size:11.5px;font-style:italic;">This attacker has not used any commands (probed via ' + escapeHtml(res.service || 'network') + ' without executing shell commands).</div>';

        const replayActionHtml = (hasCommands && res.has_replay && res.session_id)
          ? `
              <button type="button" class="btn-replay-this-ip" data-session-id="${escapeHtml(res.session_id)}" style="background:#22c55e22;border:1px solid #22c55e;color:#22c55e;font-weight:700;font-size:11px;font-family:var(--font-mono);padding:7px 16px;border-radius:4px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;">
                ▶ WATCH ATTACKER REPLAY IN CRT TERMINAL
              </button>
            `
          : `
              <span style="font-size:11px;color:#64748b;font-family:var(--font-mono);font-style:italic;">
                This attacker has not used any commands
              </span>
            `;

        searchResults.innerHTML = `
          <div style="background:#0b1120;border:1px solid #1e293b;border-radius:8px;padding:14px 16px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
              <div>
                <strong style="font-size:16px;color:#f8fafc;font-family:var(--font-mono);">${escapeHtml(res.ip)}</strong>
                <span style="margin-left:10px;font-size:12px;color:#94a3b8;">${escapeHtml(res.city)}, ${escapeHtml(res.country)} (${escapeHtml(res.isp)})</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:11px;font-family:var(--font-mono);color:#cbd5e1;">Caught by: <strong style="color:#38bdf8;">${escapeHtml(res.origin_node)}</strong></span>
                <span class="fed-role-badge hub" style="color:${riskColor(res.risk_score)};border-color:${riskColor(res.risk_score)};">${res.risk_score} / 100 RISK</span>
              </div>
            </div>

            <div style="font-size:11px;color:#94a3b8;font-family:var(--font-mono);">
              <strong>Captured Attacker Commands:</strong>
              ${cmdHtml}
            </div>

            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;border-top:1px solid #1e293b;padding-top:10px;flex-wrap:wrap;gap:8px;">
              <span style="font-size:10.5px;color:#64748b;font-family:var(--font-mono);">Trapped Intrusions: ${res.total_attacks} · Service: ${escapeHtml(res.service)}</span>
              ${replayActionHtml}
            </div>
          </div>
        `;

        if (hasCommands && res.has_replay) {
          searchResults.querySelector('.btn-replay-this-ip')?.addEventListener('click', (e) => {
            const sid = e.currentTarget.dataset.sessionId;
            closeModal();
            window.openTerminalReplayModal(sid);
          });
        }
      } catch (err) {
        searchResults.innerHTML = '<p style="color:#ef4444;font-size:11px;">Error performing cross-node threat search.</p>';
      }
    }

    btnSearchIp?.addEventListener('click', () => performIpSearch());
    searchInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        performIpSearch();
      }
    });

    // Load initial federation mesh data for the dashboard bar
    loadFederationData();

    btnToggle?.addEventListener('click', openModal);
    $('#btn-dash-open-fed')?.addEventListener('click', openModal);
    btnClose?.addEventListener('click', closeModal);
    backdrop?.addEventListener('click', closeModal);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.hidden) closeModal();
    });

    $('#btn-fed-seed-demo')?.addEventListener('click', async () => {
      try {
        if (statusNote) statusNote.textContent = 'Seeding global demo nodes...';
        const res = await fetch('/api/federation/nodes/seed-demo', { method: 'POST' }).then((r) => r.json());
        if (res.status === 'success') {
          if (statusNote) statusNote.textContent = 'Global demo sensor nodes connected!';
          await loadFederationData();
        }
      } catch (err) {
        if (statusNote) statusNote.textContent = 'Error seeding demo nodes.';
      }
    });

    $('#btn-fed-sync-now')?.addEventListener('click', async () => {
      try {
        if (statusNote) statusNote.textContent = 'Synchronizing threat intelligence mesh across nodes...';
        const res = await fetch('/api/federation/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ origin_node: 'manual-sync-trigger' })
        }).then((r) => r.json());

        if (res.status === 'success') {
          if (statusNote) statusNote.textContent = 'Threat mesh synchronized! All node IoCs active.';
          await loadFederationData();
          refreshBlockedIps();
        }
      } catch (err) {
        if (statusNote) statusNote.textContent = 'Sync communication completed.';
      }
    });

    $('#fed-register-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const node_id = $('#fed-input-id')?.value.trim();
      const node_name = $('#fed-input-name')?.value.trim();
      const region = $('#fed-input-region')?.value.trim();
      const endpoint_url = $('#fed-input-url')?.value.trim();

      if (!node_id) return;
      try {
        if (statusNote) statusNote.textContent = 'Registering remote sensor...';
        const res = await fetch('/api/federation/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ node_id, node_name, region, endpoint_url })
        }).then((r) => r.json());

        if (res.status === 'success') {
          if (statusNote) statusNote.textContent = `Node '${node_id}' registered and activated!`;
          $('#fed-register-form').reset();
          await loadFederationData();
        } else {
          if (statusNote) statusNote.textContent = res.error || 'Failed to register node.';
        }
      } catch (err) {
        if (statusNote) statusNote.textContent = 'Registration failed: ' + err.message;
      }
    });
  }

  // Start initialization
  initReplayModal();
  initFederationModal();
  loadInitialData();
})();
