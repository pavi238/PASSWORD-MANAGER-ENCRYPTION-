/**
 * app.js — Secure Vault Frontend Application
 * ============================================
 * Single-page application logic for the Password Manager.
 * Manages view transitions, API communication, credential CRUD,
 * password generation, clipboard integration, and toast notifications.
 */

(function () {
    "use strict";

    // ================================================================
    //  DOM References
    // ================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const views = {
        setup: $("#setup-view"),
        login: $("#login-view"),
        dashboard: $("#dashboard-view"),
    };

    const modals = {
        credential: $("#credential-modal"),
        delete: $("#delete-modal"),
        generator: $("#generator-modal"),
        changePassword: $("#change-pw-modal"),
    };

    // ================================================================
    //  State
    // ================================================================
    let credentials = [];
    let deleteTargetId = null;
    let generatorCallback = null; // optional callback when using generator from add/edit modal

    // ================================================================
    //  API Helper
    // ================================================================
    async function api(endpoint, options = {}) {
        const { method = "GET", body } = options;
        const config = {
            method,
            headers: { "Content-Type": "application/json" },
        };
        if (body) config.body = JSON.stringify(body);

        try {
            const res = await fetch(endpoint, config);
            const data = await res.json();
            if (!res.ok) {
                throw { status: res.status, ...data };
            }
            return data;
        } catch (err) {
            if (err.message && !err.success) {
                throw err;
            }
            throw { success: false, message: err.message || "Network error" };
        }
    }

    // ================================================================
    //  View Management
    // ================================================================
    function showView(name) {
        Object.values(views).forEach((v) => (v.style.display = "none"));
        if (views[name]) {
            views[name].style.display = "";
            views[name].style.animation = "none";
            // Force reflow to restart animation
            void views[name].offsetHeight;
            views[name].style.animation = "";
        }
    }

    async function initApp() {
        try {
            const status = await api("/api/status");
            if (!status.setup_complete) {
                showView("setup");
            } else if (!status.logged_in) {
                showView("login");
            } else {
                showView("dashboard");
                await loadCredentials();
            }
        } catch {
            showView("login");
        }
    }

    // ================================================================
    //  Toast Notifications
    // ================================================================
    function toast(message, type = "info") {
        const container = $("#toast-container");
        const el = document.createElement("div");
        el.className = `toast toast-${type}`;
        el.textContent = message;
        container.appendChild(el);

        setTimeout(() => {
            el.classList.add("toast-exit");
            el.addEventListener("animationend", () => el.remove());
        }, 3500);
    }

    // ================================================================
    //  Password Visibility Toggle
    // ================================================================
    document.addEventListener("click", (e) => {
        const btn = e.target.closest(".toggle-visibility");
        if (!btn) return;

        const targetId = btn.dataset.target;
        const input = document.getElementById(targetId);
        if (!input) return;

        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";

        const eyeIcon = btn.querySelector(".eye-icon");
        const eyeOffIcon = btn.querySelector(".eye-off-icon");
        if (eyeIcon && eyeOffIcon) {
            eyeIcon.style.display = isPassword ? "none" : "";
            eyeOffIcon.style.display = isPassword ? "" : "none";
        }
    });

    // ================================================================
    //  Strength Bar Updates
    // ================================================================
    async function updateStrengthBar(password, barEl, labelEl) {
        if (!password) {
            barEl.style.width = "0%";
            barEl.style.backgroundColor = "transparent";
            labelEl.textContent = "";
            return;
        }

        try {
            const data = await api("/api/check-strength", {
                method: "POST",
                body: { password },
            });

            const score = data.score;
            barEl.style.width = score + "%";

            let color;
            if (score >= 80) color = "var(--strength-very-strong)";
            else if (score >= 60) color = "var(--strength-strong)";
            else if (score >= 40) color = "var(--strength-medium)";
            else color = "var(--strength-weak)";

            barEl.style.backgroundColor = color;
            labelEl.textContent = `${data.rating} — ${score}/100`;
        } catch {
            labelEl.textContent = "";
        }
    }

    // ================================================================
    //  SETUP VIEW
    // ================================================================
    const setupForm = $("#setup-form");
    const setupPassword = $("#setup-password");
    const setupConfirm = $("#setup-confirm");
    const setupBtn = $("#setup-btn");

    function updateSetupRequirements() {
        const pw = setupPassword.value;
        const reqs = {
            length: pw.length >= 8,
            upper: /[A-Z]/.test(pw),
            lower: /[a-z]/.test(pw),
            digit: /\d/.test(pw),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~`]/.test(pw),
        };

        let allMet = true;
        for (const [key, met] of Object.entries(reqs)) {
            const el = $(`.req-item[data-req="${key}"]`);
            if (el) {
                el.classList.toggle("met", met);
                el.querySelector(".req-icon").textContent = met ? "✓" : "○";
            }
            if (!met) allMet = false;
        }

        const passwordsMatch =
            setupConfirm.value.length > 0 &&
            setupPassword.value === setupConfirm.value;

        setupBtn.disabled = !(allMet && passwordsMatch);

        updateStrengthBar(
            pw,
            $("#setup-strength-bar"),
            $("#setup-strength-label")
        );
    }

    setupPassword.addEventListener("input", updateSetupRequirements);
    setupConfirm.addEventListener("input", updateSetupRequirements);

    setupForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        setupBtn.disabled = true;
        setupBtn.innerHTML = '<span class="spinner"></span> Creating...';

        try {
            await api("/api/setup", {
                method: "POST",
                body: {
                    password: setupPassword.value,
                    confirm: setupConfirm.value,
                },
            });
            toast("Vault created successfully!", "success");
            showView("dashboard");
            await loadCredentials();
        } catch (err) {
            const msg =
                err.issues?.join(", ") || err.message || "Setup failed";
            toast(msg, "error");
        } finally {
            setupBtn.disabled = false;
            setupBtn.innerHTML =
                '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Create Vault';
        }
    });

    // ================================================================
    //  LOGIN VIEW
    // ================================================================
    const loginForm = $("#login-form");
    const loginPassword = $("#login-password");
    const loginBtn = $("#login-btn");
    const loginError = $("#login-error");

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        loginBtn.disabled = true;
        loginBtn.innerHTML = '<span class="spinner"></span> Unlocking...';
        loginError.style.display = "none";

        try {
            await api("/api/login", {
                method: "POST",
                body: { password: loginPassword.value },
            });
            loginPassword.value = "";
            toast("Vault unlocked", "success");
            showView("dashboard");
            await loadCredentials();
        } catch (err) {
            loginError.textContent =
                err.message || "Incorrect master password";
            loginError.style.display = "";
        } finally {
            loginBtn.disabled = false;
            loginBtn.innerHTML =
                '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Unlock';
        }
    });

    // ================================================================
    //  DASHBOARD — Load & Render Credentials
    // ================================================================
    async function loadCredentials() {
        try {
            const data = await api("/api/credentials");
            credentials = data.credentials || [];
            renderCredentials(credentials);
            updateStats();
        } catch (err) {
            if (err.status === 401) {
                showView("login");
                return;
            }
            toast("Failed to load credentials", "error");
        }
    }

    function renderCredentials(list) {
        const container = $("#credentials-list");
        const empty = $("#credentials-empty");

        if (list.length === 0) {
            container.innerHTML = "";
            empty.style.display = "";
            return;
        }

        empty.style.display = "none";
        container.innerHTML = list.map(credentialCardHTML).join("");
    }

    // Avatar color palette — deterministic based on first char
    const avatarColors = [
        "linear-gradient(135deg, #6366f1, #8b5cf6)",
        "linear-gradient(135deg, #06b6d4, #0891b2)",
        "linear-gradient(135deg, #10b981, #059669)",
        "linear-gradient(135deg, #f59e0b, #d97706)",
        "linear-gradient(135deg, #ef4444, #dc2626)",
        "linear-gradient(135deg, #ec4899, #db2777)",
        "linear-gradient(135deg, #8b5cf6, #7c3aed)",
        "linear-gradient(135deg, #14b8a6, #0d9488)",
    ];

    function getAvatarColor(service) {
        const code = service.charCodeAt(0) || 0;
        return avatarColors[code % avatarColors.length];
    }

    function credentialCardHTML(cred) {
        const initial = (cred.service || "?")[0].toUpperCase();
        const bg = getAvatarColor(cred.service);
        const masked = "•".repeat(Math.min(cred.password.length, 14));

        return `
        <div class="credential-card" data-id="${cred.id}">
            <div class="cred-avatar" style="background:${bg}">${initial}</div>
            <div class="cred-details">
                <div class="cred-service">${escapeHtml(cred.service)}</div>
                <div class="cred-username">${escapeHtml(cred.username)}</div>
                <div class="cred-password-row">
                    <span class="cred-password" data-password="${escapeAttr(cred.password)}">${masked}</span>
                    <button class="btn-icon btn-reveal" title="Reveal password" aria-label="Toggle password">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                </div>
                <div class="cred-meta">Updated ${escapeHtml(cred.updated_at || cred.created_at || "")}</div>
            </div>
            <div class="cred-actions">
                <button class="btn-icon btn-copy-pw" title="Copy password" aria-label="Copy password">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                </button>
                <button class="btn-icon btn-copy-user" title="Copy username" aria-label="Copy username">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </button>
                <button class="btn-icon btn-edit-cred" title="Edit" aria-label="Edit credential">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                </button>
                <button class="btn-icon btn-delete-cred btn-danger-text" title="Delete" aria-label="Delete credential">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                </button>
            </div>
        </div>`;
    }

    function updateStats() {
        $("#stat-total").textContent = credentials.length;
        if (credentials.length > 0) {
            const latest = credentials.reduce((a, b) =>
                (b.updated_at || "") > (a.updated_at || "") ? b : a
            );
            $("#stat-last-updated").textContent = formatRelativeTime(
                latest.updated_at || latest.created_at
            );
        } else {
            $("#stat-last-updated").textContent = "—";
        }
    }

    function formatRelativeTime(dateStr) {
        if (!dateStr) return "—";
        // Just show a concise date/time
        const parts = dateStr.split(" ");
        if (parts.length === 2) {
            return parts[0]; // Just the date part
        }
        return dateStr;
    }

    // ================================================================
    //  DASHBOARD — Event Delegation for Credential Actions
    // ================================================================
    $("#credentials-list").addEventListener("click", (e) => {
        const card = e.target.closest(".credential-card");
        if (!card) return;
        const id = parseInt(card.dataset.id, 10);
        const cred = credentials.find((c) => c.id === id);
        if (!cred) return;

        // Reveal / Hide password
        if (e.target.closest(".btn-reveal")) {
            const pwEl = card.querySelector(".cred-password");
            const isRevealed = pwEl.classList.contains("revealed");
            if (isRevealed) {
                pwEl.textContent = "•".repeat(
                    Math.min(cred.password.length, 14)
                );
                pwEl.classList.remove("revealed");
            } else {
                pwEl.textContent = cred.password;
                pwEl.classList.add("revealed");
            }
            return;
        }

        // Copy password
        if (e.target.closest(".btn-copy-pw")) {
            copyToClipboard(cred.password, `Password for ${cred.service} copied!`);
            return;
        }

        // Copy username
        if (e.target.closest(".btn-copy-user")) {
            copyToClipboard(cred.username, `Username for ${cred.service} copied!`);
            return;
        }

        // Edit
        if (e.target.closest(".btn-edit-cred")) {
            openCredentialModal("edit", cred);
            return;
        }

        // Delete
        if (e.target.closest(".btn-delete-cred")) {
            openDeleteModal(cred);
            return;
        }
    });

    // ================================================================
    //  Clipboard
    // ================================================================
    async function copyToClipboard(text, message) {
        try {
            await navigator.clipboard.writeText(text);
            toast(message || "Copied!", "success");
        } catch {
            toast("Clipboard access denied", "error");
        }
    }

    // ================================================================
    //  SEARCH
    // ================================================================
    const searchInput = $("#search-input");
    let searchTimer = null;

    searchInput.addEventListener("input", () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            const q = searchInput.value.trim().toLowerCase();
            if (!q) {
                renderCredentials(credentials);
                return;
            }
            const filtered = credentials.filter(
                (c) =>
                    c.service.toLowerCase().includes(q) ||
                    c.username.toLowerCase().includes(q)
            );
            renderCredentials(filtered);
        }, 200);
    });

    // Ctrl+K shortcut
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
            e.preventDefault();
            searchInput.focus();
        }
        // Escape to close modals
        if (e.key === "Escape") {
            closeAllModals();
        }
    });

    // ================================================================
    //  MODAL UTILITIES
    // ================================================================
    function openModal(modalEl) {
        modalEl.style.display = "";
        // Focus first input if exists
        const firstInput = modalEl.querySelector(
            'input:not([type="hidden"]):not([type="range"]):not([type="checkbox"])'
        );
        if (firstInput) setTimeout(() => firstInput.focus(), 100);
    }

    function closeModal(modalEl) {
        modalEl.style.display = "none";
    }

    function closeAllModals() {
        Object.values(modals).forEach((m) => (m.style.display = "none"));
    }

    // Close buttons + overlay click
    document.addEventListener("click", (e) => {
        if (
            e.target.classList.contains("modal-close") ||
            e.target.classList.contains("modal-cancel")
        ) {
            const overlay = e.target.closest(".modal-overlay");
            if (overlay) closeModal(overlay);
            return;
        }
        // Click on overlay background
        if (e.target.classList.contains("modal-overlay")) {
            closeModal(e.target);
        }
    });

    // ================================================================
    //  ADD / EDIT CREDENTIAL MODAL
    // ================================================================
    const credentialForm = $("#credential-form");
    const modalTitle = $("#modal-title");
    const modalCredId = $("#modal-cred-id");
    const modalService = $("#modal-service");
    const modalUsername = $("#modal-username");
    const modalPassword = $("#modal-password");
    const modalSaveBtn = $("#modal-save-btn");

    function openCredentialModal(mode, cred = null) {
        credentialForm.reset();
        if (mode === "edit" && cred) {
            modalTitle.textContent = "Edit Credential";
            modalCredId.value = cred.id;
            modalService.value = cred.service;
            modalUsername.value = cred.username;
            modalPassword.value = cred.password;
            modalSaveBtn.textContent = "Save Changes";
        } else {
            modalTitle.textContent = "Add Credential";
            modalCredId.value = "";
            modalSaveBtn.textContent = "Save Credential";
        }
        // Reset strength bar
        $("#modal-strength-bar").style.width = "0%";
        $("#modal-strength-label").textContent = "";
        openModal(modals.credential);
    }

    // Strength bar on modal password
    modalPassword.addEventListener("input", () => {
        updateStrengthBar(
            modalPassword.value,
            $("#modal-strength-bar"),
            $("#modal-strength-label")
        );
    });

    // Generate button inside modal
    $("#modal-generate-btn").addEventListener("click", () => {
        generatorCallback = (password) => {
            modalPassword.value = password;
            modalPassword.dispatchEvent(new Event("input"));
        };
        openModal(modals.generator);
        generatePassword();
    });

    $("#btn-add").addEventListener("click", () =>
        openCredentialModal("add")
    );

    credentialForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id = modalCredId.value;
        const body = {
            service: modalService.value.trim(),
            username: modalUsername.value.trim(),
            password: modalPassword.value,
        };

        modalSaveBtn.disabled = true;

        try {
            if (id !== "") {
                await api(`/api/credentials/${id}`, {
                    method: "PUT",
                    body,
                });
                toast("Credential updated", "success");
            } else {
                await api("/api/credentials", { method: "POST", body });
                toast("Credential saved", "success");
            }
            closeModal(modals.credential);
            await loadCredentials();
        } catch (err) {
            toast(err.message || "Failed to save", "error");
        } finally {
            modalSaveBtn.disabled = false;
        }
    });

    // ================================================================
    //  DELETE MODAL
    // ================================================================
    function openDeleteModal(cred) {
        deleteTargetId = cred.id;
        $("#delete-service-name").textContent = cred.service;
        openModal(modals.delete);
    }

    $("#delete-confirm-btn").addEventListener("click", async () => {
        if (deleteTargetId === null) return;

        const btn = $("#delete-confirm-btn");
        btn.disabled = true;

        try {
            await api(`/api/credentials/${deleteTargetId}`, {
                method: "DELETE",
            });
            toast("Credential deleted", "success");
            closeModal(modals.delete);
            await loadCredentials();
        } catch (err) {
            toast(err.message || "Failed to delete", "error");
        } finally {
            btn.disabled = false;
            deleteTargetId = null;
        }
    });

    // ================================================================
    //  PASSWORD GENERATOR MODAL
    // ================================================================
    const genLengthSlider = $("#gen-length");
    const genLengthValue = $("#gen-length-value");
    const genPasswordOutput = $("#gen-password-output");

    genLengthSlider.addEventListener("input", () => {
        genLengthValue.textContent = genLengthSlider.value;
    });

    async function generatePassword() {
        const body = {
            length: parseInt(genLengthSlider.value, 10),
            uppercase: $("#gen-uppercase").checked,
            lowercase: $("#gen-lowercase").checked,
            digits: $("#gen-digits").checked,
            symbols: $("#gen-symbols").checked,
        };

        try {
            const data = await api("/api/generate", {
                method: "POST",
                body,
            });
            genPasswordOutput.textContent = data.password;

            const score = data.strength.score;
            const bar = $("#gen-strength-bar");
            bar.style.width = score + "%";

            let color;
            if (score >= 80) color = "var(--strength-very-strong)";
            else if (score >= 60) color = "var(--strength-strong)";
            else if (score >= 40) color = "var(--strength-medium)";
            else color = "var(--strength-weak)";
            bar.style.backgroundColor = color;

            $("#gen-strength-label").textContent = `${data.strength.rating} — ${score}/100`;

            // Show "Use" button if opened from add/edit modal
            $("#gen-use-btn").style.display = generatorCallback
                ? ""
                : "none";
        } catch (err) {
            toast(err.message || "Generation failed", "error");
        }
    }

    // Open standalone generator
    $("#btn-generate-nav").addEventListener("click", () => {
        generatorCallback = null;
        openModal(modals.generator);
        generatePassword();
    });

    $("#gen-regenerate-btn").addEventListener("click", generatePassword);

    $("#gen-copy-btn").addEventListener("click", () => {
        const pw = genPasswordOutput.textContent;
        if (pw && pw !== "Click Generate") {
            copyToClipboard(pw, "Password copied!");
        }
    });

    $("#gen-use-btn").addEventListener("click", () => {
        const pw = genPasswordOutput.textContent;
        if (pw && generatorCallback) {
            generatorCallback(pw);
            generatorCallback = null;
        }
        closeModal(modals.generator);
    });

    // ================================================================
    //  CHANGE MASTER PASSWORD MODAL
    // ================================================================
    $("#btn-change-pw").addEventListener("click", () => {
        $("#change-pw-form").reset();
        $("#change-strength-bar").style.width = "0%";
        $("#change-strength-label").textContent = "";
        openModal(modals.changePassword);
    });

    $("#change-new").addEventListener("input", () => {
        updateStrengthBar(
            $("#change-new").value,
            $("#change-strength-bar"),
            $("#change-strength-label")
        );
    });

    $("#change-pw-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const btn = e.target.querySelector('button[type="submit"]');
        btn.disabled = true;

        try {
            await api("/api/change-password", {
                method: "POST",
                body: {
                    current_password: $("#change-current").value,
                    new_password: $("#change-new").value,
                    confirm_password: $("#change-confirm").value,
                },
            });
            toast("Master password changed!", "success");
            closeModal(modals.changePassword);
        } catch (err) {
            const msg =
                err.issues?.join(", ") || err.message || "Failed to change";
            toast(msg, "error");
        } finally {
            btn.disabled = false;
        }
    });

    // ================================================================
    //  LOGOUT
    // ================================================================
    $("#btn-logout").addEventListener("click", async () => {
        try {
            await api("/api/logout", { method: "POST" });
        } catch {
            // ignore
        }
        credentials = [];
        showView("login");
        toast("Vault locked", "info");
    });

    // ================================================================
    //  Utility Functions
    // ================================================================
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    // ================================================================
    //  Bootstrap
    // ================================================================
    initApp();
})();
