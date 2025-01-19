function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};
document.getElementById("whitelist-btn").addEventListener("click", () => {
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const blocked = result.blocked;
  
        if (blocked.length > 0) {
            const lastBlocked = blocked[blocked.length - 1].url;
            const BasedBlockURL = getBaseUrl(lastBlocked);
            console.log(`Последний заблокированный URL: ${lastBlocked}`);
  
            chrome.storage.local.get("whitelist", (result) => {
                const whitelist = result.whitelist || [];
                if (!whitelist.includes(lastBlocked)) {
                    whitelist.push(lastBlocked);
                    whitelist.push(BasedBlockURL);
                    chrome.storage.local.set({ whitelist }, () => {
                        console.log(`URL ${lastBlocked} добавлен в whitelist.`);
                    });
                } else {
                    console.log(`URL ${lastBlocked} уже существует в whitelist.`);
                }
            });
        }
    });
});
