document.addEventListener("DOMContentLoaded", () => {
  const animatedElements = document.querySelectorAll(".card, .about, .callout, header .overlay, h2, footer, #metrics, #copilot");

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

  animatedElements.forEach(el => observer.observe(el));

  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute("href"));
      if (target) {
        target.scrollIntoView({ behavior: "smooth" });
      }
    });
  });

  const ctx = document.getElementById("metricsChart");
  if (ctx) {
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Defense", "Intel", "Forensics", "Payloads", "C2", "Threats"],
        datasets: [{
          label: "Module Coverage",
          data: [12, 8, 5, 11, 7, 6],
          backgroundColor: "#1abc9c",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: "Module Category Distribution",
            color: "#ffffff",
            font: { size: 16 }
          }
        },
        scales: {
          x: {
            ticks: { color: "#ccc" },
            grid: { color: "#333" }
          },
          y: {
            ticks: { color: "#ccc" },
            grid: { color: "#333" },
            beginAtZero: true
          }
        }
      }
    });
  }

  const input = document.getElementById("copilotInput");
  const output = document.getElementById("copilotOutput");

  if (input && output) {
    input.addEventListener("keydown", async e => {
      if (e.key === "Enter") {
        const prompt = input.value.trim();
        if (!prompt) return;

        output.textContent = "Analyzing...";
        input.disabled = true;

        setTimeout(() => {
          output.textContent = `Suggested action:\n→ Run telemetry anomaly scan\n→ Monitor GNSS spoof guard\n→ Correlate logs in Copilot dashboard`;
          input.disabled = false;
          input.value = "";
        }, 1400);
      }
    });
  }

  tsParticles.load("tsparticles", {
    fullScreen: { enable: false },
    background: { color: "transparent" },
    particles: {
      number: { value: 40 },
      color: { value: "#1abc9c" },
      shape: { type: "circle" },
      opacity: { value: 0.5 },
      size: { value: 3 },
      move: {
        enable: true,
        speed: 1,
        direction: "none",
        outModes: { default: "bounce" }
      },
      links: {
        enable: true,
        distance: 100,
        color: "#1abc9c",
        opacity: 0.4,
        width: 1
      }
    },
    interactivity: {
      events: {
        onHover: { enable: true, mode: "repulse" },
        onClick: { enable: true, mode: "push" }
      },
      modes: {
        repulse: { distance: 100 },
        push: { quantity: 3 }
      }
    }
  });
});
