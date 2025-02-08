function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};
document.getElementById("whitelist-btn").addEventListener("click", () => {
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const blocked = result.blocked;

        if (blocked.length > 0) {
            const lastBlocked = blocked[blocked.length - 1]
            const ALLURL = lastBlocked.ALLURL;
            console.log(`Последний заблокированный URL: ${ALLURL}`);

            chrome.storage.local.get("whitelist", (result) => {
                const whitelist = result.whitelist || [];
                if (!whitelist.includes(ALLURL)) {
                    whitelist.push(ALLURL);
                    chrome.storage.local.set({ whitelist }, () => {
                        console.log(`URL ${ALLURL} добавлен в whitelist.`);
                    });
                } else {
                    console.log(`URL ${ALLURL} уже существует в whitelist.`);
                }
            });
        }
    });
});


document.getElementById("whitelist-btn-domen").addEventListener("click", () => {
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const blocked = result.blocked;

        if (blocked.length > 0) {
            const lastBlocked = blocked[blocked.length - 1].url;
            const BasedBlockURL = getBaseUrl(lastBlocked);
            console.log(`Последний заблокированный URL: ${lastBlocked}`);

            chrome.storage.local.get("whitelist", (result) => {
                const whitelist = result.whitelist || [];
                if (!whitelist.includes(lastBlocked)) {
                    whitelist.push(BasedBlockURL);
                    chrome.storage.local.set({ whitelist }, () => {
                        console.log(`домен ${lastBlocked} добавлен в whitelist.`);
                    });
                } else {
                    console.log(`домен ${lastBlocked} уже существует в whitelist.`);
                }
            });
        }
    });
});


document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const list = document.getElementById('reasons-list');
        const li = document.createElement('li');
        
        if (result.blocked.length > 0) {
            const lastItem = result.blocked[result.blocked.length - 1];
            const DetailedResult = lastItem.DetailedResult || [];
            let malicious = "";
            let suspicious = "";

            if (DetailedResult.length > 0) {
                for (let i = 0; i < DetailedResult.length; i++) {
                    const strLine = DetailedResult[i];
                    const curntLine = strLine.split(": ");
                    const check_list = curntLine[0];
                    const ans = curntLine[1];

                    if (ans === "malicious") {
                        malicious += `${check_list}, `;
                    }
                    if (ans === "suspicious" || ans === "phishing") {
                        suspicious += `${check_list}, `;
                    }
                }
                malicious = malicious.slice(0, -2);
                suspicious = suspicious.slice(0, -2);
            }
            
            if (malicious.length > 0 && suspicious.length > 0){
                li.textContent =
                    `Опасный: ${malicious} 
                  Подозрительный: ${suspicious}`;
                list.appendChild(li);
            } else if (malicious.length === 0){
                li.textContent =
                    `Подозрительный: ${suspicious}`;
                list.appendChild(li);
            }else if (suspicious.length === 0){
                li.textContent =
                    `Опасный: ${malicious}`;
                list.appendChild(li);
            }
        }
    });
});
