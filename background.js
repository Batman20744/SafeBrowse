chrome.runtime.onInstalled.addListener(async () => {
    const data = await chrome.storage.local.get(["scanHistory"]);

    if (!Array.isArray(data.scanHistory)) {
        await chrome.storage.local.set({
            scanHistory: []
        });
    }

    console.log("SafeBrowse v1.0.0 installed.");
});
