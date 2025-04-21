document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      let url = tabs[0].url;
      document.getElementById("url-text").textContent = url;

      fetch("http://127.0.0.1:5000/check_url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url }),
      })
      .then(response => response.json())
      .then(data => {
          const statusText = document.getElementById("status-text");
          const statusIcon = document.getElementById("status-icon");

          if (data.phishing) {
              statusText.textContent = "⚠️ This site is unsafe!";
              statusText.style.color = "red";
              statusIcon.src = "danger_icon.png";
          } else {
              statusText.textContent = "✅ This site is safe.";
              statusText.style.color = "green";
              statusIcon.src = "safe_icon.png";
          }
      })
      .catch(error => {
          console.error("Error:", error);
          document.getElementById("status-text").textContent = "Error checking site.";
      });
  });
});
// Function to update the popup with phishing detection results
function updatePopup(url, phishing, isHovered = false) {
if (isHovered) {
  // Update hovered link section
  const hoveredStatusText = document.getElementById("hovered-status-text");
  const hoveredUrlText = document.getElementById("hovered-url-text");
  const hoveredStatusIcon = document.getElementById("hovered-status-icon");

  hoveredUrlText.textContent = url;

  if (phishing) {
    hoveredStatusText.textContent = "⚠️ Phishing link detected!";
    hoveredStatusText.style.color = "red";
    hoveredStatusIcon.src = "danger_icon.png";
  } else {
    hoveredStatusText.textContent = "✅ Safe link.";
    hoveredStatusText.style.color = "green";
    hoveredStatusIcon.src = "safe_icon.png";
  }
} else {
  // Update current tab section
  const statusText = document.getElementById("status-text");
  const urlText = document.getElementById("url-text");
  const statusIcon = document.getElementById("status-icon");

  urlText.textContent = url;

  if (phishing) {
    statusText.textContent = "⚠️ This site is unsafe!";
    statusText.style.color = "red";
    statusIcon.src = "danger_icon.png";
  } else {
    statusText.textContent = "✅ This site is safe.";
    statusText.style.color = "green";
    statusIcon.src = "safe_icon.png";
  }
}
}

// Check the current tab's URL when the popup is opened
document.addEventListener("DOMContentLoaded", function () {
chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
  const url = tabs[0].url;

  // Send the current tab's URL to the backend
  chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
    console.log("Current Tab Backend Response:", response);
    updatePopup(url, response.phishing);
  });
});
});

chrome.runtime.onMessage.addListener((message) => {
if (message.action === "update_popup") {
  updatePopup(message.url, message.phishing, true);
}
});

document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = function() {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));

      this.classList.add('active');
      document.getElementById(this.dataset.target).classList.add('active');
  };
});
