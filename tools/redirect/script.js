document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("url-input");
    const paramInput = document.getElementById("param-input");
    const testBtn = document.getElementById("test-btn");
    const clearBtn = document.getElementById("clear-btn");
    const resultsContainer = document.getElementById("results");
    const previewFrame = document.getElementById("redirect-frame");
  
    const API_BASE = "https://openredirect.vercel.app/api/check.js";
  
    testBtn.addEventListener("click", async () => {
      const baseUrl = urlInput.value.trim();
      const paramList = paramInput.value.trim();
  
      if (!baseUrl || !paramList) {
        showNotification("Please enter both the URL and parameter list.", "error");
        return;
      }
  
      resultsContainer.textContent = "Testing...";
  
      const apiUrl = `${API_BASE}?url=${encodeURIComponent(baseUrl)}&params=${encodeURIComponent(paramList)}`;
  
      try {
        const res = await fetch(apiUrl);
        const data = await res.json();
  
        if (data.error) {
          resultsContainer.innerHTML = `<span class="error">Error: ${data.error}</span>`;
        } else {
          const htmlResults = data.results
            .map(
              r =>
                `<div><code>${r.payload}</code> → <strong>${r.status}</strong></div>`
            )
            .join("");
  
          resultsContainer.innerHTML = htmlResults;
  
          // preview the first working redirect
          const success = data.results.find(r => r.status === "redirect");
          if (success) {
            previewFrame.src = success.payload;
          } else {
            previewFrame.removeAttribute("src");
          }
        }
      } catch (err) {
        resultsContainer.innerHTML = `<span class="error">Request failed: ${err.message}</span>`;
      }
    });
  
    clearBtn.addEventListener("click", () => {
      urlInput.value = "";
      paramInput.value = "";
      resultsContainer.textContent = "Test results will appear here.";
      previewFrame.removeAttribute("src");
    });
  
    function showNotification(message, type = "info") {
      const n = document.createElement("div");
      n.className = `notification ${type}`;
      n.textContent = message;
      document.body.appendChild(n);
      setTimeout(() => n.classList.add("show"), 10);
      setTimeout(() => {
        n.classList.remove("show");
        setTimeout(() => n.remove(), 300);
      }, 3000);
    }
  });
  