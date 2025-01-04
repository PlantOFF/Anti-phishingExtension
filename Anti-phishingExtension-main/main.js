const apiKey = "5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a";
// cd87ccaf0717dec26cdb5aef31d5468323f915836465dd49bed358233ef45239
const apiUrl = "https://www.virustotal.com/api/v3/urls";
var black_list = ["chrome://extensions/", "about:blank", "chrome://newtab/",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/blockURL.html",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/history.html",
    "chrome-extension://inlnholhelnepdinmgbennhcjpbokbmg/html/history.html"
];


// Функция кодирования URL
function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


// Проверка наличия в черном листе
function CheckBlackList(url){
    for (var i = 0; i < black_list.length; i++){
        if (url === black_list[i]){
            return false;
    }};
    return true;
};


// Получение глобального URL
function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};


function addToWhitelist() {
    alert("Сайт добавлен в whitelist!");
    // Здесь вы можете добавить логику для работы с whitelist
}


// Функция для проверки безопасности URL
async function checkUrlSafety(url) {
    try {
        const encodedUrl = encodeUrl(url);
        console.log(`Кодированный url: ${encodedUrl}`);

        const response = await fetch(`${apiUrl}/${encodedUrl}`, {
            method: "GET",
            headers: {
                "x-apikey": apiKey,
            },
        });

        if (response.status === 404) {
            console.log("Ошибка (404 от API)\n Вероятно, такого сайта нет в базе");
            return null;
        }
        if (response.status === 429) {
            console.log("Слишком много попыток");
            return null;
        }

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;

        return [stats.harmless, stats.suspicious, stats.malicious];
    } catch (error) {
        console.log("Ошибка на стороне расширения (ответ от API не получен)");
        return null;
    }
}   


// Обработчик для вкладки
async function handleTabUpdate(tabId, tab) {
    try {
        if (!tab || !tab.url) {
            console.error("Не удалось получить URL активной вкладки.");
            return;
        }

        let currentURL = tab.url;
        console.log(`Текущий url: ${currentURL}`);
        let BasedURL = currentURL;
        currentURL = getBaseUrl(currentURL);
        console.log("Проверяемый URL: " + currentURL)
        
        if (currentURL && CheckBlackList(currentURL) && CheckBlackList(BasedURL)) {
            console.log("URL нет в черном списке")
            let safetyResult = await checkUrlSafety(currentURL);
            if (safetyResult) {
                console.log("Получен ответ:\n" +
                    "Безопасные: " + safetyResult[0] + "\n" +
                    "Подозрительные: " + safetyResult[1] + "\n" +
                    "Опасные: " + safetyResult[2]);

                if (safetyResult[2] > 2 || safetyResult[1] > 2) {
                    chrome.tabs.update(tabId, { url: 'html/blockURL.html' });
                    console.log("URL заблокирован.");

                    chrome.storage.local.get({ blocked: [] }, (result) => {
                        let blocked = result.blocked;
                        blocked.push({ url: currentURL, time: new Date().toLocaleString() });
                        chrome.storage.local.set({ blocked: blocked });
                    });
                }
                return;
            }
        } else {
            console.log("URL в черном списке");
        }
    } catch (error) {
        console.error("Ошибка в функции обработчика вкладки");
    }
}


// Обновление вкладок
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        handleTabUpdate(tabId, tab);
    }
});
