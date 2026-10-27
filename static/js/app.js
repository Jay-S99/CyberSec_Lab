(() => {
  const toggle = document.querySelector(".nav-toggle");
  const navigation = document.querySelector("#primary-navigation");

  if (toggle && navigation) {
    const closeNavigation = () => {
      toggle.setAttribute("aria-expanded", "false");
      navigation.classList.remove("is-open");
    };

    toggle.addEventListener("click", () => {
      const isOpen = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!isOpen));
      navigation.classList.toggle("is-open", !isOpen);
    });

    navigation.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", closeNavigation);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && navigation.classList.contains("is-open")) {
        closeNavigation();
        toggle.focus();
      }
    });
  }

  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (form.dataset.submitting === "true") {
        event.preventDefault();
        return;
      }
      if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
        event.preventDefault();
        return;
      }
      if (form.hasAttribute("data-credential-provision-form")) {
        const provision = form.querySelector("#provision");
        if (provision && provision.checked) {
          form.target = "_blank";
          form.rel = "noopener";
        } else {
          form.removeAttribute("target");
          form.removeAttribute("rel");
        }
      }
      form.dataset.submitting = "true";
      window.setTimeout(() => {
        form.querySelectorAll("button[type='submit'], input[type='submit']")
          .forEach((control) => {
            control.disabled = true;
            control.setAttribute("aria-busy", "true");
          });
      }, 0);
    });
  });

  const credential = document.querySelector("[data-one-time-credential]");
  if (credential) {
    const returnUrl = credential.dataset.returnUrl;
    if (returnUrl) {
      window.history.replaceState(null, "", returnUrl);
    }
    const copyButton = credential.querySelector("[data-copy-credential]");
    const password = credential.querySelector("#temporary-password");
    if (copyButton && password) {
      copyButton.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(password.textContent.trim());
          copyButton.textContent = copyButton.dataset.copiedLabel;
        } catch (_error) {
          const selection = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(password);
          selection.removeAllRanges();
          selection.addRange(range);
          copyButton.textContent = copyButton.dataset.copyLabel;
        }
      });
    }
  }
})();
