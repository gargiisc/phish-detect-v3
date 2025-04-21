chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "check_url") {
      const url = message.url;
      console.log("Received URL to check:", url); 
  
      // Send the URL to the backend for analysis
      fetch("http://127.0.0.1:5000/check_url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }),
      })
        .then((response) => response.json())
        .then((data) => {
          console.log("Backend response:", data); 
          sendResponse({ phishing: data.phishing });
  
          
          // Forward the result to the popup
          chrome.runtime.sendMessage({
            action: "update_popup",
            url: url,
            phishing: data.phishing,
          });
        })
        .catch((error) => {
          console.error("Error checking URL:", error);
          sendResponse({ phishing: false }); 
  
          chrome.runtime.sendMessage({
            action: "update_popup",
            url: url,
            phishing: false,
          });
        });
        
  
      // Return true to indicate that the response will be sent asynchronously
      return true;
    }
  });