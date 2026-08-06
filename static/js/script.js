/* ==========================================================================
   CipherGuard — Password Strength Checker
   Script: script.js
   Handles: theme toggle, live analysis (debounced API calls),
            password generator, visibility toggle, copy-to-clipboard.
   ========================================================================== */

(function () {
  "use strict";

  /* -----------------------------------------------------------------
     0. DOM REFERENCES
  ----------------------------------------------------------------- */
  const themeToggle = document.getElementById("themeToggle");
  const htmlEl = document.documentElement;

  const passwordInput = document.getElementById("passwordInput");
  const toggleVisibilityBtn = document.getElementById("toggleVisibility");
  const copyPasswordBtn = document.getElementById("copyPassword");

  const strengthMeterFill = document.getElementById("strengthMeterFill");
  const strengthLabel = document.getElementById("strengthLabel");
  const strengthScore = document.getElementById("strengthScore");
  const commonWarning = document.getElementById("commonWarning");

  const metricLength = document.getElementById("metricLength");
  const metricEntropy = document.getElementById("metricEntropy");
  const metricSecurity = document.getElementById("metricSecurity");
  const metricComplexity = document.getElementById("metricComplexity");
  const metricCrackTime = document.getElementById("metricCrackTime");

  const suggestionsList = document.getElementById("suggestionsList");

  const checklistMap = {
    chkLower: "has_lower",
    chkUpper: "has_upper",
    chkNumber: "has_number",
    chkSpecial: "has_special",
  };
  // Inverted checks: item is "valid" (green) when the flag is FALSE
  const invertedChecklistMap = {
    chkSequential: "has_sequential",
    chkKeyboard: "has_keyboard_pattern",
    chkRepeated: "has_repeated",
    chkCommon: "is_common",
  };

  // Generator elements
  const lengthSlider = document.getElementById("lengthSlider");
  const lengthValue = document.getElementById("lengthValue");
  const optUpper = document.getElementById("optUpper");
  const optLower = document.getElementById("optLower");
  const optNumbers = document.getElementById("optNumbers");
  const optSymbols = document.getElementById("optSymbols");
  const generateBtn = document.getElementById("generateBtn");
  const regenerateBtn = document.getElementById("regenerateBtn");
  const generatedOutput = document.getElementById("generatedPasswordOutput");
  const copyGeneratedBtn = document.getElementById("copyGenerated");
  const genStrengthFill = document.getElementById("genStrengthFill");
  const genStrengthLabel = document.getElementById("genStrengthLabel");
  const generatorError = document.getElementById("generatorError");

  /* -----------------------------------------------------------------
     1. THEME TOGGLE (persisted in localStorage)
  ----------------------------------------------------------------- */
  function initTheme() {
    const saved = localStorage.getItem("cipherguard-theme");
    const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    const initial = saved || (prefersLight ? "light" : "dark");
    htmlEl.setAttribute("data-theme", initial);
  }

  function toggleTheme() {
    const current = htmlEl.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    htmlEl.setAttribute("data-theme", next);
    localStorage.setItem("cipherguard-theme", next);
  }

  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);
  }
  initTheme();

  /* -----------------------------------------------------------------
     2. UTILITIES
  ----------------------------------------------------------------- */

  /** Simple debounce so we don't spam the API on every keystroke. */
  function debounce(fn, delay) {
    let timer = null;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  /** Maps a strength label to a CSS color variable. */
  function colorForLabel(label) {
    switch (label) {
      case "Very Weak": return "var(--accent-danger)";
      case "Weak": return "var(--accent-danger)";
      case "Medium": return "var(--accent-warning)";
      case "Strong": return "var(--accent-secondary)";
      case "Very Strong": return "var(--accent-success)";
      default: return "var(--accent-danger)";
    }
  }

  /** Briefly flashes a button's icon to a checkmark to confirm copy. */
  function flashCopied(button) {
    const icon = button.querySelector("i");
    if (!icon) return;
    const originalClass = icon.className;
    icon.className = "fa-solid fa-check";
    button.title = "Copied!";
    setTimeout(() => {
      icon.className = originalClass;
      button.title = "Copy Password";
    }, 1500);
  }

  async function copyToClipboard(text) {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // Fallback for older browsers / non-secure contexts
      try {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        return true;
      } catch (fallbackErr) {
        console.error("Copy failed:", fallbackErr);
        return false;
      }
    }
  }

  /* -----------------------------------------------------------------
     3. PASSWORD VISIBILITY TOGGLE
  ----------------------------------------------------------------- */
  if (toggleVisibilityBtn && passwordInput) {
    toggleVisibilityBtn.addEventListener("click", () => {
      const isPassword = passwordInput.type === "password";
      passwordInput.type = isPassword ? "text" : "password";
      const icon = toggleVisibilityBtn.querySelector("i");
      icon.className = isPassword ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
    });
  }

  /* -----------------------------------------------------------------
     4. COPY MAIN PASSWORD INPUT
  ----------------------------------------------------------------- */
  if (copyPasswordBtn && passwordInput) {
    copyPasswordBtn.addEventListener("click", async () => {
      const value = passwordInput.value;
      if (!value) return;
      const success = await copyToClipboard(value);
      if (success) flashCopied(copyPasswordBtn);
    });
  }

  /* -----------------------------------------------------------------
     5. LIVE PASSWORD ANALYSIS (calls Flask /api/analyze)
  ----------------------------------------------------------------- */
  function resetCheckerUI() {
    strengthMeterFill.style.width = "0%";
    strengthMeterFill.style.backgroundColor = "var(--accent-danger)";
    strengthLabel.textContent = "Enter a password to begin";
    strengthScore.textContent = "0 / 100";
    commonWarning.classList.add("d-none");

    metricLength.textContent = "0";
    metricEntropy.textContent = "0 bits";
    metricSecurity.textContent = "0%";
    metricComplexity.textContent = "—";
    metricCrackTime.textContent = "—";

    Object.keys(checklistMap).forEach((id) => {
      document.getElementById(id).classList.remove("valid");
    });
    Object.keys(invertedChecklistMap).forEach((id) => {
      document.getElementById(id).classList.remove("valid");
    });

    suggestionsList.innerHTML = "<li>Start typing above to see personalized suggestions.</li>";
  }

  function updateCheckerUI(data) {
    // Strength meter
    strengthMeterFill.style.width = data.score + "%";
    strengthMeterFill.style.backgroundColor = colorForLabel(data.strength_label);
    strengthLabel.textContent = data.strength_label;
    strengthLabel.style.color = colorForLabel(data.strength_label);
    strengthScore.textContent = data.score + " / 100";

    // Common password warning
    if (data.details.is_common) {
      commonWarning.classList.remove("d-none");
    } else {
      commonWarning.classList.add("d-none");
    }

    // Metrics
    metricLength.textContent = data.details.length;
    metricEntropy.textContent = data.entropy + " bits";
    metricSecurity.textContent = data.security_percentage + "%";
    metricComplexity.textContent = data.complexity_rating;
    metricCrackTime.textContent = data.crack_time;

    // Checklist — direct flags (true = valid)
    Object.entries(checklistMap).forEach(([elId, flagKey]) => {
      const el = document.getElementById(elId);
      el.classList.toggle("valid", Boolean(data.details[flagKey]));
    });

    // Checklist — inverted flags (false = valid, meaning the issue is absent)
    Object.entries(invertedChecklistMap).forEach(([elId, flagKey]) => {
      const el = document.getElementById(elId);
      const hasIssue = Boolean(data.details[flagKey]);
      el.classList.toggle("valid", data.details.length > 0 && !hasIssue);
    });

    // Suggestions
    suggestionsList.innerHTML = "";
    data.feedback.forEach((tip) => {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsList.appendChild(li);
    });
  }

  async function analyzePassword(password) {
    if (password.length === 0) {
      resetCheckerUI();
      return;
    }
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        console.error("Analyze error:", errData.error || response.statusText);
        return;
      }

      const data = await response.json();
      updateCheckerUI(data);
    } catch (err) {
      console.error("Network error while analyzing password:", err);
    }
  }

  const debouncedAnalyze = debounce((value) => analyzePassword(value), 200);

  if (passwordInput) {
    passwordInput.addEventListener("input", (e) => {
      debouncedAnalyze(e.target.value);
    });
  }

  /* -----------------------------------------------------------------
     6. PASSWORD GENERATOR (calls Flask /api/generate)
  ----------------------------------------------------------------- */
  if (lengthSlider && lengthValue) {
    lengthSlider.addEventListener("input", () => {
      lengthValue.textContent = lengthSlider.value;
    });
  }

  function getGeneratorOptions() {
    return {
      length: parseInt(lengthSlider.value, 10),
      uppercase: optUpper.checked,
      lowercase: optLower.checked,
      numbers: optNumbers.checked,
      symbols: optSymbols.checked,
    };
  }

  async function generatePassword() {
    const options = getGeneratorOptions();

    if (!options.uppercase && !options.lowercase && !options.numbers && !options.symbols) {
      generatorError.classList.remove("d-none");
      return;
    }
    generatorError.classList.add("d-none");

    try {
      const response = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        generatorError.textContent = errData.error || "Something went wrong. Please try again.";
        generatorError.classList.remove("d-none");
        return;
      }

      const data = await response.json();
      generatedOutput.value = data.password;

      // Update the mini strength meter for the generated password
      genStrengthFill.style.width = data.analysis.score + "%";
      genStrengthFill.style.backgroundColor = colorForLabel(data.analysis.strength_label);
      genStrengthLabel.textContent = data.analysis.strength_label + " (" + data.analysis.score + "/100)";
      genStrengthLabel.style.color = colorForLabel(data.analysis.strength_label);
    } catch (err) {
      console.error("Network error while generating password:", err);
      generatorError.textContent = "Network error. Please check your connection and try again.";
      generatorError.classList.remove("d-none");
    }
  }

  if (generateBtn) generateBtn.addEventListener("click", generatePassword);
  if (regenerateBtn) regenerateBtn.addEventListener("click", generatePassword);

  if (copyGeneratedBtn && generatedOutput) {
    copyGeneratedBtn.addEventListener("click", async () => {
      const value = generatedOutput.value;
      if (!value) return;
      const success = await copyToClipboard(value);
      if (success) flashCopied(copyGeneratedBtn);
    });
  }

  /* -----------------------------------------------------------------
     7. INITIAL STATE
  ----------------------------------------------------------------- */
  resetCheckerUI();

  // Generate one password automatically on load so the generator
  // section never looks empty.
  window.addEventListener("DOMContentLoaded", () => {
    generatePassword();
  });
})();
