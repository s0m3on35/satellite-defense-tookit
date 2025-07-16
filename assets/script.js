document.addEventListener("DOMContentLoaded", () => {
  const animatedElements = document.querySelectorAll(".card, .about, .callout, header .overlay, h2, footer");

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.animationPlayState = "running";
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.15
  });

  animatedElements.forEach(el => {
    observer.observe(el);
  });

  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute("href"));
      if (target) {
        target.scrollIntoView({ behavior: "smooth" });
      }
    });
  });

  const copilotInput = document.getElementById("copilot-input");
  const copilotSend = document.getElementById("copilot-send");
  const copilotMessages = document.getElementById("copilot-messages");

  if (copilotInput && copilotSend && copilotMessages) {
    copilotSend.addEventListener("click", () => {
      const message = copilotInput.value.trim();
      if (!message) return;

      const userMsg = document.createElement("div");
      userMsg.textContent = "> " + message;
      copilotMessages.appendChild(userMsg);

      const response = document.createElement("div");
      response.textContent = "Copilot is thinking...";
      copilotMessages.appendChild(response);

      copilotMessages.scrollTop = copilotMessages.scrollHeight;
      copilotInput.value = "";

      setTimeout(() => {
        response.textContent = "Response not available in demo mode.";
      }, 1000);
    });
  }
});
