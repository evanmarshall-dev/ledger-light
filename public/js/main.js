// Client-side validation and flash behavior
// Guard so this file can be required in a Node environment for static checks.
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    // Auto-dismiss flash messages after a delay, and allow manual close
    const FLASH_TIMEOUT = 6000;
    document.querySelectorAll(".flash").forEach((f) => {
      const close = document.createElement("button");
      close.className = "close";
      close.type = "button";
      close.textContent = "×";
      close.setAttribute("aria-label", "Dismiss");
      close.addEventListener("click", () => dismissFlash(f));
      f.appendChild(close);
      setTimeout(() => dismissFlash(f), FLASH_TIMEOUT);
    });

    function dismissFlash(el) {
      el.style.animation = "flash-out 220ms ease forwards";
      setTimeout(() => el.remove(), 250);
    }

    // Live validation for auth forms (email format + password strength)
    document.querySelectorAll('form[data-validate="auth"]').forEach((form) => {
      const email = form.querySelector('[name="email"]');
      const password = form.querySelector('[name="password"]');

      // create strength meter element for password
      let meter = null;
      if (password) {
        meter = document.createElement("div");
        meter.className = "password-meter";
        meter.setAttribute("aria-hidden", "false");
        password.insertAdjacentElement("afterend", meter);
      }

      const validateEmail = (val) => {
        if (!val) return { ok: false, msg: "Email is required" };
        // simple email regex
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(val)
          ? { ok: true }
          : { ok: false, msg: "Enter a valid email" };
      };

      const strength = (pw) => {
        let score = 0;
        if (!pw) return { score, label: "Too short" };
        if (pw.length >= 8) score++;
        if (/[A-Z]/.test(pw)) score++;
        if (/[0-9]/.test(pw)) score++;
        if (/[^A-Za-z0-9]/.test(pw)) score++;
        if (score <= 1) return { score, label: "Weak" };
        if (score === 2) return { score, label: "Okay" };
        return { score, label: "Strong" };
      };

      const updatePasswordMeter = (pw) => {
        if (!meter) return;
        const s = strength(pw);
        meter.textContent = s.label;
        meter.classList.remove(
          "strength-weak",
          "strength-medium",
          "strength-strong"
        );
        if (s.label === "Weak" || s.label === "Too short")
          meter.classList.add("strength-weak");
        else if (s.label === "Okay") meter.classList.add("strength-medium");
        else meter.classList.add("strength-strong");
      };

      if (email) {
        email.addEventListener("input", (e) => {
          const res = validateEmail(e.target.value);
          email.setAttribute("aria-invalid", res.ok ? "false" : "true");
          // show inline hint
          let hint = form.querySelector(`#${email.name}-hint`);
          if (!hint) {
            hint = document.createElement("div");
            hint.id = `${email.name}-hint`;
            hint.className = "field-error";
            email.insertAdjacentElement("afterend", hint);
            email.setAttribute("aria-describedby", hint.id);
          }
          hint.textContent = res.ok ? "" : res.msg;
        });
      }

      if (password) {
        password.addEventListener("input", (e) => {
          updatePasswordMeter(e.target.value);
          password.setAttribute(
            "aria-invalid",
            e.target.value.length >= 8 ? "false" : "true"
          );
          // show a small hint text
          let ph = form.querySelector(`#${password.name}-hint`);
          if (!ph) {
            ph = document.createElement("div");
            ph.id = `${password.name}-hint`;
            ph.className = "field-error";
            password.insertAdjacentElement("afterend", ph);
            password.setAttribute("aria-describedby", ph.id);
          }
          ph.textContent =
            e.target.value.length >= 8
              ? ""
              : "Password should be at least 8 characters";
        });
      }

      form.addEventListener("submit", (e) => {
        const errors = [];
        if (email) {
          const r = validateEmail(email.value);
          if (!r.ok) errors.push(r.msg);
        }
        if (password) {
          const s = strength(password.value);
          if (s.score < 2)
            errors.push(
              "Choose a stronger password (min 8 chars, mix of letters and numbers)"
            );
        }
        if (errors.length) {
          e.preventDefault();
          // reuse showClientErrors to display messages
          showClientErrors(form, errors);
        }
      });
    });

    // Simple client-side validation for transaction forms
    document
      .querySelectorAll('form[data-validate="transaction"]')
      .forEach((form) => {
        form.addEventListener("submit", (e) => {
          const title = form.querySelector('[name="title"]');
          const amount = form.querySelector('[name="amount"]');
          let errors = [];
          if (!title || !title.value.trim()) errors.push("Title is required");
          if (!amount || isNaN(Number(amount.value)))
            errors.push("Valid amount is required");
          if (errors.length) {
            e.preventDefault();
            // show inline errors
            showClientErrors(form, errors);
          }
        });

        // per-route CSS is now SSR-included via the head partial; no dynamic loader needed
      });

    function showClientErrors(form, errors) {
      // remove old errors
      form.querySelectorAll(".client-error").forEach((n) => n.remove());
      const container = document.createElement("div");
      container.className = "client-error";
      errors.forEach((msg) => {
        const p = document.createElement("div");
        p.className = "field-error";
        p.textContent = msg;
        container.appendChild(p);
      });
      form.insertBefore(container, form.firstChild);
      container.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  });
}
