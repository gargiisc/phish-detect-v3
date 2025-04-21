// Variable to store the last hovered URL
let lastHoveredUrl = ""; 

function sendUrlToBackend(url) {
  chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
    console.log("Backend Response:", response);
    if (response.phishing) {
      console.log(`⚠️ Warning: The link "${url}" is flagged as phishing!`);
    } else {
      console.log(`✅ The link "${url}" is safe.`);
    }
  });
}

document.addEventListener(
  "mouseover",
  (event) => {
    const target = event.target.closest("a"); 
    if (target && target.href) {
      const realUrl = target.href;
      if (realUrl !== lastHoveredUrl) {
        lastHoveredUrl = realUrl; 
        console.log("Hovered over link:", realUrl); 
        sendUrlToBackend(realUrl); 
      }
    }
  },
  true
);