// --- Global State and Constants ---
const API_BASE = window.location.origin;
let authToken = localStorage.getItem('authToken');
let jobList = []; // Cache for job data
// Search & Sort preferences
const SEARCH_SORT_STORAGE_KEY = 'jobPrefs';
const DEFAULT_PREFS = { search: '', sort: '' };
let activeSearchDelay = null;

// --- Search & Sort State Management ---

function getPrefs() {
    const stored = localStorage.getItem(SEARCH_SORT_STORAGE_KEY);
    return stored ? JSON.parse(stored) : DEFAULT_PREFS;
}

function savePrefs(prefs) {
    localStorage.setItem(SEARCH_SORT_STORAGE_KEY, JSON.stringify(prefs));
}

function updateURL(search, sort) {
    const url = new URL(window.location);
    if (search) url.searchParams.set('q', search);
    else url.searchParams.delete('q');
    if (sort) url.searchParams.set('sort', sort);
    else url.searchParams.delete('sort');
    window.history.replaceState({}, '', url);
}

// Get prefs from URL or fall back to stored/default
function getInitialPrefs() {
    const url = new URL(window.location);
    const stored = getPrefs();
    return {
        search: url.searchParams.get('q') || stored.search || DEFAULT_PREFS.search,
        sort: url.searchParams.get('sort') || stored.sort || DEFAULT_PREFS.sort
    };
}

function applyPrefsToUI(prefs) {
    const searchEl = document.getElementById('search-input');
    const sortEl = document.getElementById('sort-select');
    if (searchEl) searchEl.value = prefs.search;
    if (sortEl) sortEl.value = prefs.sort;
}

// --- Utility Functions ---

function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function renderIcon(name, classes = 'w-5 h-5') {
    const icon = lucide.icons[name];
    if (!icon) return '';
    // Ensure class includes a margin for icons used inline in text/buttons
    return icon.toSvg({ class: classes });
}

function showMessage(message, type = 'info') {
    const container = document.getElementById('app');
    let borderColor = 'border-teal-500/40';
    let iconColor = 'text-teal-400';
    let icon = 'info';
    if (type === 'success') { borderColor = 'border-emerald-500/50'; iconColor = 'text-emerald-400'; icon = 'check-circle'; }
    if (type === 'error') { borderColor = 'border-rose-500/50'; iconColor = 'text-rose-400'; icon = 'alert-triangle'; }

    const messageBox = document.createElement('div');
    // High-contrast modern glass toast message
    messageBox.className = `fixed top-20 right-4 sm:right-8 p-3.5 pr-5 bg-slate-900/95 dark:bg-slate-850/95 text-white border ${borderColor} rounded-2xl shadow-2xl z-50 backdrop-blur-md transition-all duration-300 ease-in-out transform translate-x-full opacity-0 flex items-center space-x-3 text-sm`;
    messageBox.innerHTML = `<span class="${iconColor}">${renderIcon(icon, 'w-5 h-5')}</span> <span class="font-medium text-slate-100">${escapeHtml(message)}</span>`;

    container.appendChild(messageBox);

    // Show animation
    setTimeout(() => {
        messageBox.classList.remove('translate-x-full', 'opacity-0');
        messageBox.classList.add('translate-x-0', 'opacity-100');
    }, 10);

    // Hide animation
    setTimeout(() => {
        messageBox.classList.remove('translate-x-0', 'opacity-100');
        messageBox.classList.add('translate-x-full', 'opacity-0');
        messageBox.addEventListener('transitionend', () => messageBox.remove());
    }, 3200);
}

// --- Auth & Network ---

async function authFetch(url, options = {}) {
    if (!authToken) {
        renderLogin();
        return { ok: false, status: 401, json: () => ({ error: "Not authenticated" }) };
    }

    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json',
    };

    try {
        const response = await fetch(url, options);
        if (response.status === 401) {
            // Token expired or invalid
            handleLogout();
            showMessage("Your session expired. Please log in again.", 'error');
        }
        return response;
    } catch (error) {
        console.error("Network error during fetch:", error);
        // Return a mock response object for network failures
        return { ok: false, status: 500, json: () => ({ error: "Network connection failed" }) };
    }
}

function updateAuthState(isLoggedIn) {
    const logoutBtn = document.getElementById('logout-button');
    if (isLoggedIn) {
        logoutBtn.classList.remove('hidden');
    } else {
        logoutBtn.classList.add('hidden');
    }
}

function handleLogout() {
    localStorage.removeItem('authToken');
    authToken = null;
    updateAuthState(false);
    renderLogin();
}

// --- Rendering Logic: Login ---

function renderLogin() {
    updateAuthState(false);
    const contentArea = document.getElementById('content-area');
    contentArea.innerHTML = `
        <div class="w-full max-w-sm p-8 sm:p-10 bg-white dark:bg-slate-900 rounded-3xl card space-y-6 border border-slate-200 dark:border-slate-800 shadow-2xl relative overflow-hidden">
            <div class="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-teal-500 to-emerald-500"></div>
            <div class="text-center space-y-2">
                <div class="inline-flex items-center justify-center p-2.5 rounded-2xl bg-teal-500/10 text-teal-600 dark:text-teal-400 mb-1 border border-teal-500/20">
                    ${renderIcon('sliders', 'w-6 h-6')}
                </div>
                <h2 class="text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">The Switch Access</h2>
                <p class="text-xs text-slate-500 dark:text-slate-400">Sign in to control automation jobs</p>
            </div>
            <form id="login-form" onsubmit="event.preventDefault(); handleLogin(event)" class="space-y-4">
                <div>
                    <label for="username" class="block text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Username</label>
                    <input type="text" id="username" name="username" value="admin" class="input-style" required>
                </div>
                <div>
                    <label for="password" class="block text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Password</label>
                    <input type="password" id="password" name="password" value="password" class="input-style" required>
                </div>
                <button type="submit" class="primary-btn w-full mt-6 py-3 px-4 text-white font-bold rounded-xl shadow-lg transition duration-200 flex items-center justify-center space-x-2">
                    <span>Authenticate</span>
                    ${renderIcon('arrow-right', 'w-4 h-4')}
                </button>
            </form>
            <div class="p-2.5 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200/80 dark:border-slate-800 text-center">
                <p class="text-xs text-slate-500 dark:text-slate-400">Demo defaults: <code class="text-teal-600 dark:text-teal-400 font-semibold font-mono">admin</code> / <code class="text-teal-600 dark:text-teal-400 font-semibold font-mono">password</code></p>
            </div>
        </div>
    `;
}

async function handleLogin(event) {
    const form = event.target;
    const username = form.username.value;
    const password = form.password.value;

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (response.ok) {
            authToken = result.token;
            localStorage.setItem('authToken', authToken);
            showMessage("Login successful!", 'success');
            renderDashboard();
        } else {
            showMessage(result.error || "Login failed.", 'error');
        }
    } catch (error) {
        showMessage("A network error occurred during login.", 'error');
    }
}

// --- Rendering Logic: Dashboard ---

// Helper: format seconds to short notation (d/h/m/s) for pre-filling notifyBefore
function formatSecondsToShort(sec) {
    if (!sec || sec <= 0) return '';
    if (sec % 86400 === 0) return (sec / 86400) + 'd';
    if (sec % 3600 === 0) return (sec / 3600) + 'h';
    if (sec % 60 === 0) return (sec / 60) + 'm';
    return sec + 's';
}

function renderDashboard() {
    updateAuthState(true);
    const contentArea = document.getElementById('content-area');
    const prefs = getInitialPrefs();
    contentArea.innerHTML = `
        <div class="w-full max-w-7xl space-y-6">
            <!-- Action Toolbar Banner -->
            <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center p-5 sm:p-6 bg-white dark:bg-slate-900 rounded-2xl card border border-slate-200 dark:border-slate-800 shadow-sm gap-4">
                <div>
                    <div class="flex items-center space-x-2.5">
                        <h2 class="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">Scheduled Tasks</h2>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200/60 dark:border-emerald-800/60">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 animate-pulse"></span> Active Engine
                        </span>
                    </div>
                    <p class="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1">Manage, inspect, and trigger scheduled background executions</p>
                </div>
                <button onclick="renderJobForm()" class="primary-btn px-5 py-2.5 flex items-center text-white font-bold rounded-xl shadow-md text-sm whitespace-nowrap">
                    ${renderIcon('plus', 'w-4 h-4 mr-2')} New Job
                </button>
            </div>
            <!-- Search and Filter Bar -->
            <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                <div class="relative flex-1 max-w-2xl">
                    <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                        ${renderIcon('search', 'w-4 h-4')}
                    </div>
                    <input id="search-input" type="text" placeholder="Search by title or description..." oninput="onSearchInput()" class="input-style pl-10" />
                </div>
                <div class="flex items-center space-x-2">
                    <select id="sort-select" onchange="onSortChange()" class="input-style w-full sm:w-60 font-medium text-xs sm:text-sm">
                        <option value="">Sort: Default (Newest)</option>
                        <option value="alphabetical">Alphabetical (A–Z)</option>
                        <option value="date_created">Date Created (Newest)</option>
                        <option value="date_modified">Date Modified (Newest)</option>
                        <option value="next_schedule">Next Schedule (Soonest)</option>
                    </select>
                </div>
            </div>
            <!-- Job List Container -->
            <div id="job-list-container">
                <div class="p-12 text-center bg-white dark:bg-slate-900 rounded-2xl card text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
                    ${renderIcon('loader-2', 'w-6 h-6 animate-spin mx-auto mb-2 text-teal-600 dark:text-teal-400')}
                    Loading configured jobs...
                </div>
            </div>
        </div>
    `;
    // Apply initial preferences from URL/storage
    applyPrefsToUI(prefs);
    // Initial fetch with preferences
    fetchJobs();
}

// Debounced search handler
function onSearchInput() {
    if (activeSearchDelay) clearTimeout(activeSearchDelay);
    activeSearchDelay = setTimeout(() => {
        const prefs = {
            search: document.getElementById('search-input').value,
            sort: document.getElementById('sort-select').value
        };
        savePrefs(prefs);
        updateURL(prefs.search, prefs.sort);
        fetchJobs();
    }, 300);
}

function onSortChange() {
    const prefs = {
        search: document.getElementById('search-input').value,
        sort: document.getElementById('sort-select').value
    };
    savePrefs(prefs);
    updateURL(prefs.search, prefs.sort);
    fetchJobs();
}

async function fetchJobs() {
    // Build query params from search and sort controls
    const searchEl = document.getElementById('search-input');
    const sortEl = document.getElementById('sort-select');
    const params = new URLSearchParams();
    if (searchEl && searchEl.value.trim()) params.append('q', searchEl.value.trim());
    if (sortEl && sortEl.value) params.append('sort', sortEl.value);
    let url = `${API_BASE}/api/jobs/`;
    const qs = params.toString();
    if (qs) url += '?' + qs;

    const response = await authFetch(url, { method: 'GET' });

    if (response && response.ok) {
        jobList = await response.json();
        renderJobList(jobList);
    } else if (response) {
        const error = await response.json();
        showMessage(error.error || "Failed to fetch jobs.", 'error');
        document.getElementById('job-list-container').innerHTML = `<div class="p-10 text-center bg-red-100 rounded-2xl card text-red-700 border border-red-300">Error loading jobs: ${escapeHtml(error.error || 'Check API connection.')}</div>`;
    }
}

function renderJobList(jobs) {
    const container = document.getElementById('job-list-container');

    if (jobs.length === 0) {
        container.innerHTML = `<div class="p-12 text-center bg-white dark:bg-slate-900 rounded-3xl card border border-dashed border-slate-300 dark:border-slate-800">
            <div class="p-4 bg-teal-500/10 dark:bg-teal-400/10 text-teal-600 dark:text-teal-400 rounded-2xl w-16 h-16 mx-auto mb-3 flex items-center justify-center">
                ${renderIcon('calendar-check', 'w-8 h-8')}
            </div>
            <p class="font-bold text-lg text-slate-800 dark:text-slate-200">No jobs currently scheduled</p> 
            <p class="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-sm mx-auto">Click <strong class="text-teal-600 dark:text-teal-400">'New Job'</strong> to configure your first automated background job.</p>
        </div>`;
        return;
    }

    let html = `
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    `;

    jobs.forEach(job => {
        const createdAt = new Date(job.createdAt).toLocaleString();
        const updatedAt = (job.updatedAt && job.updatedAt > 0) ? new Date(job.updatedAt).toLocaleString() : null;
        const updatedDifferent = (job.updatedAt && job.updatedAt > job.createdAt);

        let nextRunTimeDisplay = '<span class="text-slate-400">N/A</span>';
        let cronWarning = '';
        let nextRunColor = 'text-emerald-600 dark:text-emerald-400';
        let notifyHtml = '';

        if (job.nextRunAt > 0) {
            try {
                const cronDescription = cronstrue.toString(job.cronExpression, { verbose: true });
                const nextRunDate = new Date(job.nextRunAt).toLocaleString();
                nextRunTimeDisplay = `<span title="${cronDescription}" class="font-bold">${nextRunDate}</span>`;
            } catch (e) {
                nextRunTimeDisplay = '<span class="text-rose-500 font-bold">Invalid CRON</span>';
                cronWarning = `<div class="text-xs text-rose-500 flex items-center mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">${renderIcon('alert-triangle', 'w-4 h-4 mr-1.5')} Invalid CRON expression.</div>`;
                nextRunColor = 'text-rose-500';
            }
        } else if (job.nextRunAt === 0) {
            nextRunTimeDisplay = '<span class="text-rose-500 font-bold">Invalid CRON</span>';
            cronWarning = `<div class="text-xs text-rose-500 flex items-center mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">${renderIcon('alert-triangle', 'w-4 h-4 mr-1.5')} Invalid CRON expression.</div>`;
            nextRunColor = 'text-rose-500';
        }

        // Show pre-run notification info if configured (job.notifyBeforeSeconds)
        if (job.notifyBeforeSeconds && job.notifyBeforeSeconds > 0) {
            try {
                const nbShort = formatSecondsToShort(job.notifyBeforeSeconds);
                if (job.nextRunAt && job.nextRunAt > 0) {
                    const notifyAt = new Date(job.nextRunAt - job.notifyBeforeSeconds * 1000).toLocaleString();
                    notifyHtml = `<div class="mt-3 text-xs sm:text-sm text-teal-800 dark:text-teal-300 bg-teal-50/70 dark:bg-teal-950/40 border border-teal-200/70 dark:border-teal-800/60 p-2.5 rounded-xl flex items-center flex-wrap gap-1.5">${renderIcon('bell', 'w-4 h-4 mr-1 text-teal-600 dark:text-teal-400')}Notify Before: <span class="font-semibold">${escapeHtml(nbShort)}</span> — will notify at <span class="font-mono bg-teal-100 dark:bg-teal-900/60 text-teal-900 dark:text-teal-200 px-2 py-0.5 rounded-md text-xs">${escapeHtml(notifyAt)}</span></div>`;
                } else {
                    notifyHtml = `<div class="mt-3 text-xs sm:text-sm text-teal-800 dark:text-teal-300 bg-teal-50/70 dark:bg-teal-950/40 border border-teal-200/70 dark:border-teal-800/60 p-2.5 rounded-xl flex items-center">${renderIcon('bell', 'w-4 h-4 mr-1.5 text-teal-600 dark:text-teal-400')}Notify Before: <span class="font-semibold ml-1.5">${escapeHtml(nbShort)}</span></div>`;
                }
            } catch (e) {
                notifyHtml = `<div class="mt-3 text-xs text-slate-500 flex items-center">${renderIcon('bell', 'w-3.5 h-3.5 mr-1.5 text-slate-400')}Notify Before: configured</div>`;
            }
        }

        // Show post-execution notification indicator
        let notifyExecBadge = '';
        if (job.notifyOnExecution) {
            notifyExecBadge = `<span title="Post-execution notifications enabled" class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200/60 dark:border-emerald-800/60">${renderIcon('bell-ring', 'w-3 h-3 mr-1')} Notify</span>`;
        }

        html += `
            <div id="job-${escapeHtml(job.id)}" class="card bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 flex flex-col transition duration-200 hover:border-teal-500/50 dark:hover:border-teal-500/50 relative overflow-hidden group">
                <div class="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-500 to-emerald-500 opacity-60 group-hover:opacity-100 transition-opacity"></div>
                <div class="flex justify-between items-start mb-3 pt-1">
                    <h3 class="text-xl font-extrabold text-slate-900 dark:text-white leading-snug flex-1 min-w-0 mr-3 flex items-center flex-wrap">
                        ${escapeHtml(job.title)}
                        ${notifyExecBadge}
                    </h3>
                    <div class="flex space-x-1.5 flex-shrink-0">
                        <button onclick="renderJobForm('${escapeHtml(job.id)}')" title="Edit Job" class="flex items-center px-2.5 py-1 rounded-lg text-slate-500 hover:text-teal-600 hover:bg-teal-50 dark:hover:bg-teal-950/50 transition text-xs font-semibold">
                            ${renderIcon('square-pen', 'w-3.5 h-3.5 mr-1')}
                            <span>Edit</span>
                        </button>
                        <button onclick="confirmDeleteJob('${escapeHtml(job.id)}', '${escapeHtml(job.title)}')" title="Delete Job" class="flex items-center px-2.5 py-1 rounded-lg text-slate-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 transition text-xs font-semibold">
                            ${renderIcon('trash-2', 'w-3.5 h-3.5 mr-1')}
                            <span>Delete</span>
                        </button>
                    </div>
                </div>
                <p class="text-slate-500 dark:text-slate-400 mb-4 text-xs sm:text-sm line-clamp-2">${escapeHtml(job.description || 'No description provided.')}</p>
                
                <div class="grid grid-cols-2 gap-y-2.5 gap-x-3 mb-4 text-xs sm:text-sm border-t border-b py-3 border-slate-100 dark:border-slate-800/80">
                    <div class="flex items-center ${nextRunColor} font-semibold">
                        ${renderIcon('play-circle', 'w-4 h-4 mr-2 ' + nextRunColor)}
                        Next: <span class="ml-1.5">${nextRunTimeDisplay}</span>
                    </div>

                    <div class="flex items-center text-slate-700 dark:text-slate-300">
                        ${renderIcon('clock', 'w-4 h-4 mr-2 text-teal-600 dark:text-teal-400')}
                        <strong>Cron:</strong> <code class="ml-1.5 font-mono bg-teal-50 dark:bg-teal-950/60 text-teal-800 dark:text-teal-300 border border-teal-200/60 dark:border-teal-800/60 px-2 py-0.5 rounded-md text-xs font-bold">${escapeHtml(job.cronExpression)}</code>
                    </div>
                    
                    <div class="flex items-center text-slate-500 dark:text-slate-400 text-xs">
                        ${renderIcon('calendar', 'w-3.5 h-3.5 mr-1.5 text-slate-400')}
                        Created: <span class="ml-1">${createdAt}</span>
                    </div>
                    ${updatedDifferent ? `
                    <div class="flex items-center text-slate-500 dark:text-slate-400 text-xs">
                        ${renderIcon('edit-3', 'w-3.5 h-3.5 mr-1.5 text-slate-400')}
                        Modified: <span class="ml-1">${escapeHtml(updatedAt)}</span>
                    </div>
                    ` : `
                    <div class="flex items-center text-amber-600 dark:text-amber-400 font-semibold text-xs">
                        ${renderIcon('skip-forward', 'w-3.5 h-3.5 mr-1.5 text-amber-500')} Skip Count: <span id="skip-count-${escapeHtml(job.id)}" class="ml-1 font-bold text-amber-700 dark:text-amber-300">${job.skipCount}</span>
                    </div>
                    `}
                </div> 
                ${cronWarning}
                ${notifyHtml}

                <details class="mb-4 p-3.5 bg-slate-50/80 dark:bg-slate-900/60 rounded-xl border border-slate-200/80 dark:border-slate-800">
                    <summary class="font-semibold cursor-pointer text-xs sm:text-sm flex items-center text-slate-700 dark:text-slate-300 hover:text-teal-600 dark:hover:text-teal-400 transition">
                        ${renderIcon('code', 'w-4 h-4 mr-2 text-teal-600 dark:text-teal-400')} Script Content (View)
                    </summary>
                    <textarea id="script-view-${escapeHtml(job.id)}" class="script-view mt-3 text-xs p-0 bg-transparent border-0 font-mono" rows="8" readonly>${escapeHtml(job.scriptContent)}</textarea>
                </details>
                
                <!-- Action buttons (Manual Run & Skip) -->
                <div class="mt-auto flex space-x-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                    <button onclick="handleManualRun('${escapeHtml(job.id)}', '${escapeHtml(job.title)}')" class="flex-1 px-4 py-2 text-xs sm:text-sm text-teal-800 dark:text-teal-200 bg-teal-50 dark:bg-teal-950/60 border border-teal-200/80 dark:border-teal-800/60 font-bold rounded-xl hover:bg-teal-100 dark:hover:bg-teal-900/60 transition duration-150 flex items-center justify-center shadow-sm">
                        ${renderIcon('zap', 'w-3.5 h-3.5 mr-1.5 text-teal-600 dark:text-teal-400')} Run Now
                    </button>
                    <button onclick="handleSkipJob('${escapeHtml(job.id)}')" class="flex-1 px-4 py-2 text-xs sm:text-sm text-amber-800 dark:text-amber-200 bg-amber-50 dark:bg-amber-950/50 border border-amber-200/80 dark:border-amber-800/60 font-bold rounded-xl hover:bg-amber-100 dark:hover:bg-amber-900/50 transition duration-150 flex items-center justify-center shadow-sm">
                        ${renderIcon('chevrons-right', 'w-3.5 h-3.5 mr-1.5 text-amber-600 dark:text-amber-400')} Skip Next
                    </button>
                </div>
                
                <!-- Execution History Section (Modal Trigger) -->
                <div class="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                    <button onclick="showHistoryModal('${escapeHtml(job.id)}', '${escapeHtml(job.title)}')" class="w-full px-4 py-2 text-xs sm:text-sm text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700/80 border border-slate-200 dark:border-slate-700/80 font-semibold rounded-xl transition duration-150 flex items-center justify-center shadow-sm">
                        ${renderIcon('history', 'w-3.5 h-3.5 mr-2 text-slate-500 dark:text-slate-400')} View Execution History (Last 10)
                    </button>
                </div>

            </div>
        `;
    });

    html += `</div>`;
    container.innerHTML = html;
    // Initialize CodeMirror viewers for any script view textareas
    try { initScriptViewers(); } catch (e) { console.debug('initScriptViewers failed:', e); }
}

function confirmDeleteJob(jobId, jobTitle) {
    // Using a custom modal-like message box
    if (window.confirm(`Are you sure you want to delete the job '${jobTitle}'? This action cannot be undone.`)) {
        handleDeleteJob(jobId, jobTitle);
    }
}

async function handleDeleteJob(jobId, jobTitle) {
    const response = await authFetch(`${API_BASE}/api/jobs/${jobId}`, { method: 'DELETE' });

    if (response && response.status === 204) {
        showMessage(`Job '${jobTitle}' deleted successfully.`, 'success');
        // Remove job from the list immediately
        const jobElement = document.getElementById(`job-${jobId}`);
        if (jobElement) jobElement.classList.add('animate-out', 'fade-out', 'slide-out-to-right-4'); // Tailwind animation classes are not available by default, but applying a class for removal.

        // Use a short delay before actually removing the element
        setTimeout(() => {
            if (jobElement) jobElement.remove();

            // Check if the list is empty and re-render if necessary
            const jobListContainer = document.getElementById('job-list-container');
            if (jobListContainer) {
                const grid = jobListContainer.querySelector('.grid');
                if (!grid || grid.children.length === 0) {
                    fetchJobs();
                }
            }
        }, 300);

    } else if (response) {
        const error = await response.json();
        showMessage(error.error || `Failed to delete job '${jobTitle}'.`, 'error');
    }
}

async function handleSkipJob(jobId) {
    const skipElement = document.getElementById(`skip-count-${jobId}`);
    const originalCount = skipElement.textContent;
    skipElement.innerHTML = `${renderIcon('loader-2', 'w-4 h-4 animate-spin inline')}`; // Loading indicator

    const response = await authFetch(`${API_BASE}/api/jobs/${jobId}/skip`, { method: 'POST' });

    if (response && response.ok) {
        const result = await response.json();
        skipElement.textContent = result.skipCount;
        showMessage("Job skip count incremented.", 'success');
    } else {
        skipElement.textContent = originalCount;
        const error = response ? await response.json() : { error: 'Connection failed' };
        showMessage(error.error || "Failed to skip job.", 'error');
    }
}

// --- Job Form and Submission (Updated for Feature 3) ---

function getJobById(jobId) {
    return jobList.find(job => job.id === jobId);
}

// NEW: Function to add key/value inputs for EnvVars (Feature 3)
window.setCronPreset = function (expr) {
    const input = document.getElementById('cronExpression');
    if (input) {
        input.value = expr;
        input.dispatchEvent(new Event('input'));
    }
};

function addEnvVarInput(key = '', value = '', isNew = false) {
    const container = document.getElementById('env-vars-container');
    if (!container) return;

    const div = document.createElement('div');
    div.className = 'flex items-center space-x-2.5';
    const uniqueId = crypto.randomUUID();
    div.innerHTML = `
        <div class="flex-1">
            <input type="text" id="env-key-${uniqueId}" name="env-key" placeholder="KEY (e.g., API_TOKEN)" value="${escapeHtml(key)}" class="input-style font-mono text-xs">
        </div>
        <span class="text-sm font-bold text-slate-400 dark:text-slate-500">=</span>
        <div class="flex-1">
            <input type="text" id="env-value-${uniqueId}" name="env-value" placeholder="VALUE (e.g., secret123)" value="${escapeHtml(value)}" class="input-style font-mono text-xs">
        </div>
        <button type="button" onclick="this.closest('.flex').remove()" title="Remove Variable" class="p-2 text-slate-400 hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/40 rounded-xl transition">
            ${renderIcon('trash-2', 'w-4 h-4')}
        </button>
    `;
    container.appendChild(div);

    if (isNew) {
        document.getElementById(`env-key-${uniqueId}`).focus();
    }
}


async function renderJobForm(jobId = null) {
    const contentArea = document.getElementById('content-area');
    let jobData = {
        title: '',
        description: '',
        cronExpression: '* * * * * *', // Default to every second for easy testing
        scriptContent: '#!/bin/bash\necho "Hello from the new job!"',
        skipCount: 0,
        envVars: {},
        notifyBeforeSeconds: 0, // Initialize notifyBeforeSeconds for new jobs
        notifyOnExecution: false,
    };
    let isEdit = jobId !== null;

    if (isEdit) {
        jobData = getJobById(jobId);
        if (!jobData) {
            showMessage("Job not found for editing.", 'error');
            renderDashboard();
            return;
        }
    }

    contentArea.innerHTML = `
        <div class="w-full max-w-4xl p-6 sm:p-8 bg-white dark:bg-slate-900 rounded-3xl card border border-slate-200 dark:border-slate-800 shadow-xl space-y-6 relative overflow-hidden">
            <div class="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-500 to-emerald-500"></div>
            
            <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
                <div>
                    <h2 class="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">${isEdit ? 'Edit Automation Job' : 'Create Automation Job'}</h2>
                    <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${isEdit ? 'Update job schedule, script, and notification rules' : 'Set up a new recurring schedule and script payload'}</p>
                </div>
                <button type="button" onclick="renderDashboard()" class="px-3.5 py-1.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-semibold rounded-xl transition flex items-center shadow-sm">
                    ${renderIcon('arrow-left', 'w-3.5 h-3.5 mr-1.5')} Back to List
                </button>
            </div>
            
            <form id="job-form" onsubmit="event.preventDefault(); handleJobSubmit(event, '${jobId || ''}')" class="w-full space-y-6">
                
                <!-- Core Details & Schedule Grid -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
                    <!-- Left Column: Title & Description -->
                    <div class="space-y-4">
                        <div>
                            <label for="title" class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-1.5">Job Title <span class="text-rose-500">*</span></label>
                            <input type="text" id="title" name="title" value="${escapeHtml(jobData.title)}" class="input-style" placeholder="e.g. Database Backup & Sync" required>
                        </div>
                        <div>
                            <label for="description" class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-1.5">Description</label>
                            <textarea id="description" name="description" rows="3" class="input-style resize-none" placeholder="Brief summary of what this job does...">${escapeHtml(jobData.description)}</textarea>
                        </div>
                    </div>

                    <!-- Right Column: CRON Schedule -->
                    <div class="space-y-3 flex flex-col justify-between">
                        <div>
                            <label for="cronExpression" class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-1.5">CRON Expression (6 fields) <span class="text-rose-500">*</span></label>
                            <input type="text" id="cronExpression" name="cronExpression" value="${escapeHtml(jobData.cronExpression)}" class="input-style font-mono text-sm" placeholder="* * * * * *" required>
                            
                            <!-- Quick Preset Chips -->
                            <div class="flex flex-wrap items-center gap-1.5 mt-2">
                                <span class="text-[11px] font-medium text-slate-400 mr-1">Presets:</span>
                                <button type="button" onclick="setCronPreset('* * * * * *')" class="px-2 py-0.5 text-[11px] font-mono rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-teal-50 dark:hover:bg-teal-950/60 hover:text-teal-700 dark:hover:text-teal-300 border border-slate-200/80 dark:border-slate-700/80 transition">Every sec</button>
                                <button type="button" onclick="setCronPreset('0 * * * * *')" class="px-2 py-0.5 text-[11px] font-mono rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-teal-50 dark:hover:bg-teal-950/60 hover:text-teal-700 dark:hover:text-teal-300 border border-slate-200/80 dark:border-slate-700/80 transition">Every min</button>
                                <button type="button" onclick="setCronPreset('0 0 * * * *')" class="px-2 py-0.5 text-[11px] font-mono rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-teal-50 dark:hover:bg-teal-950/60 hover:text-teal-700 dark:hover:text-teal-300 border border-slate-200/80 dark:border-slate-700/80 transition">Every hour</button>
                                <button type="button" onclick="setCronPreset('0 0 0 * * *')" class="px-2 py-0.5 text-[11px] font-mono rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-teal-50 dark:hover:bg-teal-950/60 hover:text-teal-700 dark:hover:text-teal-300 border border-slate-200/80 dark:border-slate-700/80 transition">Midnight</button>
                            </div>
                        </div>

                        <!-- Live CRON preview card -->
                        <div class="p-3 rounded-xl bg-teal-50/70 dark:bg-teal-950/30 border border-teal-200/80 dark:border-teal-800/60 flex items-start space-x-2">
                            <span class="text-teal-600 dark:text-teal-400 mt-0.5">${renderIcon('clock', 'w-4 h-4')}</span>
                            <p id="cron-description" class="text-xs font-semibold text-teal-900 dark:text-teal-200 flex-1 leading-snug">Parsing CRON expression...</p>
                        </div>
                    </div>
                </div>

                <!-- Notifications & Reminders Panel -->
                <div class="p-4 sm:p-5 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800 space-y-3">
                    <div class="flex items-center space-x-2">
                        <span class="text-teal-600 dark:text-teal-400">${renderIcon('bell', 'w-4 h-4')}</span>
                        <label class="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">Telegram Notifications & Reminders</label>
                    </div>
                    
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                        <div>
                            <label for="notifyBefore" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Pre-run Reminder</label>
                            <input type="text" id="notifyBefore" name="notifyBefore" placeholder="e.g. 5m, 1h, 1d" value="${escapeHtml(formatSecondsToShort(jobData.notifyBeforeSeconds || 0))}" class="input-style font-mono text-xs sm:text-sm" />
                            <p id="notify-info" class="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Leave empty or set reminder lead time (e.g., <code class="text-teal-600 dark:text-teal-400 font-bold">10m</code>, <code class="text-teal-600 dark:text-teal-400 font-bold">1h</code>)</p>
                            <p id="notify-warning" class="text-xs mt-1 hidden"></p>
                        </div>

                        <div class="flex items-center pt-2 sm:pt-4">
                            <label class="relative flex items-center cursor-pointer select-none">
                                <input type="checkbox" id="notifyOnExecution" name="notifyOnExecution" class="w-4 h-4 text-teal-600 rounded focus:ring-teal-500 border-slate-300 dark:border-slate-700 cursor-pointer" ${jobData.notifyOnExecution ? 'checked' : ''}>
                                <div class="ml-2.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                                    <span>Notify after execution</span>
                                    <p class="text-[11px] font-normal text-slate-500 dark:text-slate-400">Send Telegram alert with execution status (Success/Failure)</p>
                                </div>
                            </label>
                        </div>
                    </div>
                </div>

                <!-- Shell Script Section -->
                <div class="space-y-2">
                    <div class="flex justify-between items-center">
                        <label class="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center">
                            ${renderIcon('terminal', 'w-4 h-4 mr-1.5 text-teal-600 dark:text-teal-400')} Shell Script Content
                        </label>
                        <span class="text-[11px] font-mono px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200/80 dark:border-slate-700/80">/bin/bash</span>
                    </div>
                    
                    <div class="rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div class="bg-slate-100/90 dark:bg-slate-950 px-4 py-2 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
                            <div class="flex items-center space-x-1.5">
                                <span class="w-2.5 h-2.5 rounded-full bg-slate-300 dark:bg-slate-700 inline-block"></span>
                                <span class="w-2.5 h-2.5 rounded-full bg-slate-300 dark:bg-slate-700 inline-block"></span>
                                <span class="w-2.5 h-2.5 rounded-full bg-slate-300 dark:bg-slate-700 inline-block"></span>
                                <span class="text-xs font-mono text-slate-500 dark:text-slate-400 ml-2">payload.sh</span>
                            </div>
                            <span class="text-[11px] text-slate-400 font-mono">Syntax Highlighted</span>
                        </div>
                        <textarea id="scriptContent" name="scriptContent" rows="8" class="input-style font-mono text-sm resize-none border-0 rounded-none" required>${escapeHtml(jobData.scriptContent)}</textarea>
                    </div>
                </div>

                <!-- Environment Variables Section -->
                <div class="space-y-2">
                    <div class="flex justify-between items-center">
                        <div>
                            <label class="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center">
                                ${renderIcon('lock', 'w-4 h-4 mr-1.5 text-teal-600 dark:text-teal-400')} Environment Variables
                            </label>
                            <p class="text-[11px] text-slate-500 dark:text-slate-400">Injected securely into execution environment</p>
                        </div>
                        <button type="button" onclick="addEnvVarInput('', '', true)" class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 text-teal-700 dark:text-teal-300 hover:bg-teal-100 dark:hover:bg-teal-900/60 transition flex items-center shadow-sm">
                            ${renderIcon('plus', 'w-3.5 h-3.5 mr-1')} Add Variable
                        </button>
                    </div>
                    <div id="env-vars-container" class="space-y-2 pt-1">
                        <!-- Appended rows -->
                    </div>
                </div>

                ${isEdit ? `
                    <div class="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                        <div>
                            <label for="skipCount" class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Skip Next Trigger</label>
                            <p class="text-[11px] text-slate-500 dark:text-slate-400">Number of upcoming scheduled executions to skip</p>
                        </div>
                        <input type="number" id="skipCount" name="skipCount" value="${jobData.skipCount}" min="0" class="input-style w-24 font-mono text-center" required>
                    </div>
                ` : ''}

                <div class="flex justify-between items-center pt-4 border-t border-slate-100 dark:border-slate-800">
                    <button type="button" onclick="renderDashboard()" class="px-5 py-2.5 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white text-xs sm:text-sm font-semibold rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition duration-150 flex items-center">
                        ${renderIcon('arrow-left', 'w-4 h-4 mr-1.5')} Cancel
                    </button>
                    <button type="submit" id="submit-button" class="primary-btn px-6 py-2.5 flex items-center text-white font-bold rounded-xl shadow-lg transition duration-200 text-xs sm:text-sm">
                        ${isEdit ? renderIcon('save', 'w-4 h-4 mr-2') + ' Save Changes' : renderIcon('send', 'w-4 h-4 mr-2') + ' Create Job'}
                    </button>
                </div>
            </form>
        </div>
    `;

    // Function to update the CRON description in real time
    const updateCronDescription = () => {
        const cronInput = document.getElementById('cronExpression').value;
        const descElement = document.getElementById('cron-description');
        if (!descElement) return;

        // Clear previous state and add icon
        descElement.innerHTML = `${renderIcon('clock', 'w-4 h-4 mr-1.5 inline')}`;

        try {
            const descriptionText = cronstrue.toString(cronInput);
            descElement.innerHTML += ` <span>${descriptionText}</span>`;
            descElement.className = 'text-xs font-semibold text-teal-900 dark:text-teal-200 flex-1 leading-snug';
        } catch (e) {
            descElement.innerHTML += ' <span class="text-rose-500 font-bold">Invalid CRON format (must include 6 fields)</span>';
            descElement.className = 'text-xs font-semibold text-rose-600 dark:text-rose-400 flex-1 leading-snug';
        }
    };

    // Set up CRON listener
    const cronInput = document.getElementById('cronExpression');
    cronInput.addEventListener('input', updateCronDescription);
    updateCronDescription(); // Initial update

    // NotifyBefore validation: call server to compute cron interval and warn if <= 24h
    const notifyInput = document.getElementById('notifyBefore');
    const notifyWarning = document.getElementById('notify-warning');
    const notifyInfo = document.getElementById('notify-info');

    async function validateNotifyBefore() {
        const val = notifyInput.value.trim();
        notifyWarning.classList.add('hidden');
        notifyWarning.classList.remove('text-red-600');
        if (!val) return true; // nothing to validate

        // Ask server for interval between next two runs
        try {
            const resp = await authFetch(`${API_BASE}/api/cron/interval`, { method: 'POST', body: JSON.stringify({ cronExpression: cronInput.value }) });
            if (!resp || !resp.ok) {
                const err = resp ? await resp.json() : { error: 'Connection failed' };
                notifyWarning.textContent = `Could not validate schedule: ${err.error || 'Unknown error'}`;
                notifyWarning.classList.remove('hidden');
                notifyWarning.classList.add('text-yellow-600');
                return false;
            }
            const data = await resp.json();
            const intervalSec = data.intervalSeconds || 0;
            // TODO: Uncomment this if block to dont alow notification before 24 hour
            // if (intervalSec <= 86400) {
            //     notifyWarning.textContent = 'Warning: This schedule recurs every 24 hours or less; pre-run notifications are intended for jobs recurring > 24h.';
            //     notifyWarning.classList.remove('hidden');
            //     notifyWarning.classList.add('text-red-600');
            //     return false;
            // }
            // All good
            notifyWarning.classList.add('hidden');
            return true;
        } catch (e) {
            notifyWarning.textContent = 'Validation error: ' + e.message;
            notifyWarning.classList.remove('hidden');
            notifyWarning.classList.add('text-yellow-600');
            return false;
        }
    }

    if (notifyInput) {
        notifyInput.addEventListener('input', () => {
            // Debounce lightly
            if (window._notifyTimer) clearTimeout(window._notifyTimer);
            window._notifyTimer = setTimeout(() => validateNotifyBefore(), 500);
        });
    }

    // Populate EnvVars section for edit (Feature 3)
    if (isEdit && jobData.envVars && Object.keys(jobData.envVars).length > 0) {
        Object.entries(jobData.envVars).forEach(([key, value]) => {
            addEnvVarInput(key, value, false);
        });
    } else {
        // Add one empty row by default
        addEnvVarInput('', '', false);
    }
    // Initialize CodeMirror for the form script textarea (dark theme, line numbers)
    try { initScriptFormEditor(); } catch (e) { console.debug('initScriptFormEditor failed:', e); }
}


async function handleJobSubmit(event, jobId) {
    const form = event.target;
    const title = form.title.value;
    const description = form.description.value;
    const cronExpression = form.cronExpression.value;
    // If CodeMirror is active for the form, ensure textarea is synced
    if (window.cmFormEditor) {
        try { form.scriptContent.value = window.cmFormEditor.getValue(); } catch (e) { /* ignore */ }
    }
    const scriptContent = form.scriptContent.value;
    const skipCount = form.skipCount ? parseInt(form.skipCount.value) : 0;

    const submitButton = document.getElementById('submit-button');
    submitButton.disabled = true;
    const originalButtonText = submitButton.innerHTML;
    submitButton.innerHTML = `${renderIcon('loader-2', 'w-5 h-5 animate-spin mr-2')} Processing...`;

    // Extract Environment Variables (Feature 3)
    const envVars = {};
    // Select all key and value inputs by their name attribute
    const keyInputs = form.querySelectorAll('input[name="env-key"]');
    const valueInputs = form.querySelectorAll('input[name="env-value"]');

    keyInputs.forEach((keyInput, index) => {
        const key = keyInput.value.trim();
        const value = valueInputs[index].value.trim();
        if (key !== '' && value !== '') {
            envVars[key] = value;
        }
    });


    const jobData = {
        title,
        description,
        cronExpression,
        scriptContent,
        skipCount,
        // Add EnvVars to jobData
        envVars: envVars,
        // NotifyBefore short string (e.g. "5m")
        notifyBefore: form.notifyBefore ? form.notifyBefore.value.trim() : '',
        notifyOnExecution: form.notifyOnExecution ? form.notifyOnExecution.checked : false
    };

    let response;
    let method;
    let url;

    if (jobId) {
        method = 'PUT';
        url = `${API_BASE}/api/jobs/${jobId}`;
    } else {
        method = 'POST';
        url = `${API_BASE}/api/jobs/`;
    }

    try {
        // If notifyBefore present, validate schedule interval first
        if (jobData.notifyBefore) {
            const valid = await (async () => {
                try {
                    const resp = await authFetch(`${API_BASE}/api/cron/interval`, { method: 'POST', body: JSON.stringify({ cronExpression }) });
                    if (!resp || !resp.ok) {
                        const err = resp ? await resp.json() : { error: 'Connection failed' };
                        showMessage(err.error || 'Could not validate cron expression for notifyBefore.', 'error');
                        return false;
                    }
                    const data = await resp.json();
                    // TODO: Uncomment this if block to dont alow notification before 24 hour
                    // if ((data.intervalSeconds || 0) <= 86400) {
                    //     showMessage('notifyBefore is only allowed for jobs recurring greater than 24 hours.', 'error');
                    //     return false;
                    // }
                    return true;
                } catch (e) {
                    showMessage('Validation error: ' + e.message, 'error');
                    return false;
                }
            })();
            if (!valid) {
                submitButton.disabled = false;
                submitButton.innerHTML = originalButtonText;
                return;
            }
        }

        response = await authFetch(url, {
            method: method,
            body: JSON.stringify(jobData)
        });

        const result = await response.json();

        if (response.ok || response.status === 200) {
            showMessage(`Job ${jobId ? 'updated' : 'created'} successfully!`, 'success');
            renderDashboard();
        } else {
            showMessage(result.error || `Failed to ${jobId ? 'update' : 'create'} job.`, 'error');
        }
    } catch (error) {
        showMessage("A network error occurred.", 'error');
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalButtonText;
    }
}

// --- Manual Run Logic (Feature 2) ---

async function handleManualRun(jobId, jobTitle) {
    // Using a custom modal-like message box
    if (!window.confirm(`Are you sure you want to manually run job '${jobTitle}' now?`)) return;

    const runButton = document.querySelector(`#job-${jobId} button[onclick*='handleManualRun']`);
    const originalContent = runButton.innerHTML;
    runButton.disabled = true;
    runButton.innerHTML = `${renderIcon('loader-2', 'w-4 h-4 animate-spin mr-2')} Running...`;

    try {
        const response = await authFetch(`${API_BASE}/api/jobs/${jobId}/run`, { method: 'POST' });
        const result = await response.json();

        if (response.status === 202) {
            showMessage(`Job '${jobTitle}' triggered successfully!`, 'success');
        } else {
            showMessage(result.error || `Failed to trigger manual run for job '${jobTitle}'.`, 'error');
        }
    } catch (error) {
        showMessage(`A network error occurred during manual run for job '${jobTitle}'.`, 'error');
    } finally {
        runButton.disabled = false;
        runButton.innerHTML = originalContent;

        // If the history modal is open, force a refresh
        const modal = document.getElementById('history-modal');
        if (!modal.classList.contains('hidden')) {
            // Slight delay to allow backend goroutine to finish logging (optimistic approach)
            setTimeout(() => loadJobHistory(jobId), 500);
        }
    }
}

// --- History Logic (Modal Implementation) ---

async function showHistoryModal(jobId, jobTitle) {
    const modal = document.getElementById('history-modal');
    const modalTitle = document.getElementById('history-modal-title');
    const modalBody = document.getElementById('history-modal-body');

    modalTitle.textContent = `Execution History: ${jobTitle}`;

    // Show loading spinner while fetching
    modalBody.innerHTML = `<p class="text-md text-gray-500 text-center py-6">${renderIcon('loader-2', 'w-6 h-6 animate-spin inline mr-2')} Loading execution records...</p>`;

    // Show modal
    modal.classList.remove('hidden');
    document.body.classList.add('overflow-hidden'); // Prevent background scrolling

    // Fetch and render history
    await loadJobHistory(jobId);
}

function closeHistoryModal() {
    const modal = document.getElementById('history-modal');
    modal.classList.add('hidden');
    document.body.classList.remove('overflow-hidden');
    document.getElementById('history-modal-body').innerHTML = ''; // Clear content
}

async function loadJobHistory(jobId) {
    const contentDiv = document.getElementById('history-modal-body');

    const response = await authFetch(`${API_BASE}/api/jobs/${jobId}/history`, { method: 'GET' });

    if (response && response.ok) {
        const history = await response.json();
        renderHistoryListInModal(history);
    } else {
        const error = response ? await response.json() : { error: 'Connection failed' };
        contentDiv.innerHTML = `<div class="text-center p-6 text-red-500">Error: Failed to load history. ${escapeHtml(error.error || 'Unknown error')}</div>`;
    }
}

function renderHistoryListInModal(history) {
    const contentDiv = document.getElementById('history-modal-body');

    if (history.length === 0) {
        contentDiv.innerHTML = `<div class="text-center py-10">
            <div class="p-3 bg-slate-100 dark:bg-slate-800 text-slate-400 rounded-2xl w-12 h-12 mx-auto mb-2 flex items-center justify-center">
                ${renderIcon('calendar-check', 'w-6 h-6')}
            </div>
            <p class="text-sm font-semibold text-slate-700 dark:text-slate-300">No execution records found yet</p>
            <p class="text-xs text-slate-400 mt-0.5">Executions will be recorded here when triggered automatically or manually.</p>
        </div>`;
        return;
    }

    // Max height and scroll added to the content wrapper
    let html = `<div class="space-y-3 max-h-[70vh] overflow-y-auto pr-1">`;
    history.forEach(exec => {
        const isSuccess = exec.status === 'Success';
        const statusColor = isSuccess ? 'text-emerald-700 dark:text-emerald-300' : 'text-rose-700 dark:text-rose-300';
        const cardBg = isSuccess ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200/70 dark:border-emerald-900/50' : 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200/70 dark:border-rose-900/50';
        const iconName = isSuccess ? 'check-circle' : 'x-circle';
        const iconColor = isSuccess ? 'text-emerald-500' : 'text-rose-500';
        const startTime = new Date(exec.startTime).toLocaleTimeString();
        const fullDateTime = new Date(exec.startTime).toLocaleString();
        const durationSeconds = (exec.duration / 1000).toFixed(2);
        const exitCodeDisplay = exec.exitCode >= 0 ? exec.exitCode : 'N/A';

        html += `
            <details class="p-3.5 rounded-2xl ${cardBg} border shadow-sm transition">
                <summary class="text-xs sm:text-sm font-bold flex justify-between items-center cursor-pointer hover:opacity-90 transition ${statusColor}">
                    <div class="flex items-center space-x-2">
                        <span class="${iconColor}">${renderIcon(iconName, 'w-4 h-4')}</span>
                        <span class="font-extrabold">${escapeHtml(exec.status)}</span>
                        <span class="text-slate-500 dark:text-slate-400 font-normal text-xs pl-2" title="${fullDateTime}">@ ${startTime}</span>
                    </div>
                    <div class="text-slate-500 dark:text-slate-400 font-mono text-xs text-right">
                        <span>${durationSeconds}s</span> &bull; <span>Exit ${exitCodeDisplay}</span>
                    </div>
                </summary>
                <pre class="mt-3 text-xs overflow-x-auto p-3 bg-slate-900 dark:bg-slate-950 text-emerald-400 dark:text-emerald-300 rounded-xl font-mono max-h-48 whitespace-pre-wrap border border-slate-800 shadow-inner">${escapeHtml(exec.output || 'No output recorded.')}</pre>
            </details>
        `;
    });
    html += `</div>`;
    contentDiv.innerHTML = html;
}

// --- CodeMirror Initialization Helpers (light & dark theme + line numbers) ---
// initScriptViewers: initialize read-only viewers for job list items
function initScriptViewers() {
    if (typeof CodeMirror === 'undefined') return;
    window.viewerEditors = window.viewerEditors || {};
    const elems = document.querySelectorAll('.script-view');
    elems.forEach(textarea => {
        const id = textarea.id || '';
        const jobId = id.replace(/^script-view-/, '');
        if (!jobId) return;
        // If an editor was previously created for this jobId, clean it up
        if (window.viewerEditors[jobId]) {
            try {
                window.viewerEditors[jobId].toTextArea();
            } catch (e) {
                // ignore cleanup errors
            }
            delete window.viewerEditors[jobId];
        }
        try {
            const cm = CodeMirror.fromTextArea(textarea, {
                mode: 'shell',
                theme: 'default',
                lineNumbers: true,
                readOnly: true,
                viewportMargin: Infinity
            });
            cm.setSize('100%', 'auto');
            window.viewerEditors[jobId] = cm;
        } catch (e) {
            console.debug('Failed to init viewer CodeMirror for', jobId, e);
        }
    });
}

// initScriptFormEditor: initialize (or re-initialize) the editor used on create/update form
function initScriptFormEditor() {
    if (typeof CodeMirror === 'undefined') return;
    // Clean up previous editor if present
    if (window.cmFormEditor) {
        try { window.cmFormEditor.toTextArea(); } catch (e) { /* ignore */ }
        window.cmFormEditor = null;
    }
    const ta = document.getElementById('scriptContent');
    if (!ta) return;
    try {
        window.cmFormEditor = CodeMirror.fromTextArea(ta, {
            mode: 'shell',
            theme: 'default',
            lineNumbers: true,
            indentUnit: 2,
            lineWrapping: true
        });
        // Give a comfortable height for editing
        window.cmFormEditor.setSize('100%', 280);
    } catch (e) {
        console.debug('initScriptFormEditor failed:', e);
    }
}


// --- Initialization ---

// Fetch build info from the server and populate footer
async function fetchAndPopulateBuildInfo() {
    try {
        const resp = await fetch(`${window.location.origin}/buildinfo`);
        if (!resp.ok) return;
        const data = await resp.json();
        const verEl = document.getElementById('build-version');
        const revEl = document.getElementById('build-revision');
        const timeEl = document.getElementById('build-time');
        if (verEl) verEl.textContent = data.version || 'dev';
        if (revEl) revEl.textContent = data.commit || 'none';
        if (timeEl) timeEl.textContent = data.buildTime || 'unknown';
    } catch (e) {
        // Silent fail — build info is non-critical
        console.debug('Could not fetch build info:', e);
    }
}

// Check auth status on load and render the correct view
window.onload = function () {
    // Need to set the global API base for the bot.go to work in the canvas environment
    window.API_BASE = window.location.origin;

    // Populate build/version info in the footer (non-blocking)
    fetchAndPopulateBuildInfo();

    // Initialize theme
    initTheme();

    if (authToken) {
        renderDashboard();
    } else {
        renderLogin();
    }
};

// --- Theme Management ---

const THEME_STORAGE_KEY = 'theme-preference';
const THEME_LIGHT = 'light';
const THEME_DARK = 'dark';
const THEME_SYSTEM = 'system';

// Get system theme preference
function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? THEME_DARK : THEME_LIGHT;
}

// Get stored theme preference or default to system
function getThemePreference() {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored || THEME_SYSTEM;
}

// Apply theme to the document
function applyTheme(theme) {
    const htmlElement = document.documentElement;
    const themeIcon = document.getElementById('theme-icon');

    let actualTheme = theme;
    if (theme === THEME_SYSTEM) {
        actualTheme = getSystemTheme();
    }

    if (actualTheme === THEME_DARK) {
        htmlElement.classList.add('dark');
        if (themeIcon) {
            // Moon icon for dark mode
            themeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path>';
        }
    } else {
        htmlElement.classList.remove('dark');
        if (themeIcon) {
            // Sun icon for light mode
            themeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path>';
        }
    }

    // Refresh any active CodeMirror instances
    setTimeout(() => {
        if (window.cmFormEditor) {
            try { window.cmFormEditor.refresh(); } catch (e) {}
        }
        if (window.viewerEditors) {
            Object.values(window.viewerEditors).forEach(cm => {
                try { cm.refresh(); } catch (e) {}
            });
        }
    }, 50);
}

// Cycle through themes: system -> light -> dark -> system
function cycleTheme() {
    const currentPreference = getThemePreference();
    let nextTheme;

    if (currentPreference === THEME_SYSTEM) {
        nextTheme = THEME_LIGHT;
    } else if (currentPreference === THEME_LIGHT) {
        nextTheme = THEME_DARK;
    } else {
        nextTheme = THEME_SYSTEM;
    }

    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    applyTheme(nextTheme);

    // Show a subtle message indicating the theme change
    const themeNames = {
        [THEME_SYSTEM]: 'System',
        [THEME_LIGHT]: 'Light',
        [THEME_DARK]: 'Dark'
    };
    showMessage(`Theme: ${themeNames[nextTheme]}`, 'info');
}

// Initialize theme on page load
function initTheme() {
    const preference = getThemePreference();
    applyTheme(preference);

    // Set up theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', cycleTheme);
    }

    // Listen for system theme changes when in system mode
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', (e) => {
        if (getThemePreference() === THEME_SYSTEM) {
            applyTheme(THEME_SYSTEM);
        }
    });
}

// --- Settings Modal & Export/Import Logic ---

function openSettingsModal() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.classList.remove('hidden');
        setTimeout(() => {
            const content = modal.querySelector('.modal-content');
            if (content) {
                content.classList.remove('translate-y-4', 'opacity-0', 'scale-95');
            }
        }, 10);
    }
}

function closeSettingsModal() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        const content = modal.querySelector('.modal-content');
        if (content) {
            content.classList.add('translate-y-4', 'opacity-0', 'scale-95');
        }
        setTimeout(() => {
            modal.classList.add('hidden');
        }, 300);
    }
}

function handleExport() {
    if (!authToken) {
        showMessage('You must be logged in to export configuration.', 'error');
        return;
    }
    // Create a temporary link to trigger download
    // Note: We need to pass the Authorization header. 
    // Since we cannot add headers to a standard <a href> click, and we don't want to use XHR for file download if possible to keep it simple,
    // we might need to fetch as blob -> create object URL.

    fetch(`${API_BASE}/api/settings/export`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
    })
        .then(response => {
            if (!response.ok) throw new Error("Export failed");
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            // Ideally we get filename from Content-Disposition, but fallback to default
            a.download = `the_switch_config_${new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '')}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        })
        .catch(err => {
            console.error(err);
            showMessage("Failed to export configuration.", 'error');
        });
}

function handleDrop(event) {
    event.preventDefault();
    const zone = document.getElementById('drop-zone');
    if (zone) zone.classList.remove('border-teal-500', 'bg-teal-50/40', 'dark:bg-teal-950/30');

    if (event.dataTransfer.files && event.dataTransfer.files.length > 0) {
        const file = event.dataTransfer.files[0];
        uploadConfigFile(file);
    }
}

function handleFileSelect(event) {
    if (event.target.files && event.target.files.length > 0) {
        uploadConfigFile(event.target.files[0]);
    }
    // Reset input so same file can be selected again if needed
    event.target.value = '';
}

async function uploadConfigFile(file) {
    if (!file) return;

    // Optimistic UI update
    const zone = document.getElementById('drop-zone');
    const originalContent = zone ? zone.innerHTML : '';
    if (zone) {
        zone.innerHTML = `<div class="flex flex-col items-center justify-center py-6">
            ${renderIcon('loader-2', 'w-10 h-10 animate-spin text-teal-600 dark:text-teal-400 mb-3')}
            <span class="text-slate-700 dark:text-slate-300 font-semibold text-sm">Importing ${escapeHtml(file.name)}...</span>
        </div>`;
    }

    const formData = new FormData();
    formData.append('configFile', file);

    try {
        const response = await fetch(`${API_BASE}/api/settings/import`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            showMessage(result.message || "Import successful!", 'success');
            // Close modal and refresh dashboard
            closeSettingsModal();
            fetchJobs();
        } else {
            showMessage(result.error || "Import failed.", 'error');
            if (zone) zone.innerHTML = originalContent; // Restore UI
        }
    } catch (error) {
        console.error("Import error:", error);
        showMessage("Network error during import.", 'error');
        if (zone) zone.innerHTML = originalContent; // Restore UI
    }
}

// Update updateAuthState to toggle settings button visibility
const originalUpdateAuthState = updateAuthState;
updateAuthState = function (isLoggedIn) {
    // Call original implementation
    const logoutBtn = document.getElementById('logout-button');
    if (isLoggedIn) logoutBtn.classList.remove('hidden');
    else logoutBtn.classList.add('hidden');

    // Handle Settings Button
    const settingsBtn = document.getElementById('settings-button');
    if (settingsBtn) {
        if (isLoggedIn) settingsBtn.classList.remove('hidden');
        else settingsBtn.classList.add('hidden');
    }
};
