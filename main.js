const apiKey = "cd87ccaf0717dec26cdb5aef31d5468323f915836465dd49bed358233ef45239";
// 1 - 5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a
// 2 - cd87ccaf0717dec26cdb5aef31d5468323f915836465dd49bed358233ef45239

const apiUrl = "https://www.virustotal.com/api/v3/urls";
const defaultWhitelist = ["chrome://extensions", "about:blank", "chrome://newtab/",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/blockURL.html",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/history.html",
    "chrome-extension://inlnholhelnepdinmgbennhcjpbokbmg/html/history.html",
    "chrome-extension://khndaeiicffojkhnnipnfjdenhcjnham",
    "chrome-extension://lebpdbamallemffholehndlklfdffbmp/html/blockURL.html",
    "chrome-extension://lebpdbamallemffholehndlklfdffbmp"
];

const defultUserThresholds = {
    suspicious: 1,
    malicious: 0,
};


// Инициализации whitelist
chrome.storage.local.get("whitelist", (result) => {
    if (!result.whitelist) {
        chrome.storage.local.set({ whitelist: defaultWhitelist }, () => {
            console.log("Whitelist инициализирован значениями по умолчанию.");
        });
    }
});


// Инициализации порогов
function CheckThresholds() {
    return new Promise((resolve) => {
        chrome.storage.local.get("thresholds", (result) => {
            if (!result.thresholds) {
                chrome.storage.local.set({ thresholds: defultUserThresholds }, () => {
                    console.log("Инициализация значений порогов проверки по умолчанию");
                    resolve(defultUserThresholds);
                });
            } else {
                resolve(result.thresholds);
            }
        });
    });
}


// Функция для получения текущего whitelist
function getWhitelist(callback) {
    chrome.storage.local.get("whitelist", (result) => {
      const whitelist = result.whitelist || [];
      callback(whitelist);
})};


// Функция кодирования URL
function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


// Проверка наличия в белом листе
async function checkBlackList(url) {
    return new Promise((resolve) => {
        getWhitelist((whitelist) => {
            const isBlacklisted = whitelist.includes(url);
            resolve(isBlacklisted);
        });
    });
};


// Получение глобального URL
function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};


// Проверка безопасности URL
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
      const results = data.data.attributes.last_analysis_results;
  
      return [stats.harmless, stats.suspicious, stats.malicious, results];
    } catch (error) {
      console.log("Ошибка на стороне расширения (ответ от API не получен)");
      return null;
    }
};  

// Обновление вкладок
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        handleTabUpdate(tabId, tab);
    }
});


// Обработчик для вкладки
async function handleTabUpdate(tabId, tab) {
    const thresholds = await CheckThresholds();
    console.log(`Проверяемые пороги: suspicious=${thresholds.suspicious}, malicious=${thresholds.malicious}`);
    try {
        if (!tab || !tab.url) {
            console.error("Не удалось получить URL активной вкладки.");
            return;
        }

        let currentURL = tab.url;
        console.log(`Текущий url: ${currentURL}`);
        let BasedURL = currentURL;
        currentURL = getBaseUrl(currentURL);
        console.log("Проверяемый URL: " + currentURL);

        const isCurrentURLBlacklisted = await checkBlackList(currentURL);
        const isBasedURLBlacklisted = await checkBlackList(BasedURL);
        let statsWtiteList = true;

        if (currentURL && !isCurrentURLBlacklisted && !isBasedURLBlacklisted) {
            statsWtiteList = false;
            console.log("URL нет в черном списке");
            let safetyResult = await checkUrlSafety(currentURL);
            if (safetyResult) {
                console.log("Получен ответ:\n" +
                    "Безопасные: " + safetyResult[0] + "\n" +
                    "Подозрительные: " + safetyResult[1] + "\n" +
                    "Опасные: " + safetyResult[2]);

                console.log("Детальный результат проверки:");
                let DetailedResult = [];
                Object.entries(safetyResult[3]).forEach(([key, value]) => {
                    DetailedResult.push(`${key}: ${value.result}`);
                });
                console.log(DetailedResult);

                if (safetyResult[1] > thresholds.suspicious || safetyResult[2] > thresholds.malicious) {
                    chrome.tabs.update(tabId, { url: 'html/blockURL.html' });
                    chrome.storage.local.get({ blocked: [] }, (result) => {
                        let blocked = result.blocked;
                        blocked.push({
                            url: currentURL,
                            time: new Date().toLocaleString(),
                            response: safetyResult,
                            DetailedResult: DetailedResult
                        });
                        chrome.storage.local.set({ blocked: blocked });
                    });
                    console.log("URL заблокирован.");
                }
                }

            chrome.storage.local.get({ history: [] }, (result) => {
                let history = result.history;
                history.push({
                    statsWtiteList: statsWtiteList,
                    safetyResult: safetyResult,
                    currentURL: currentURL,
                    BasedURL: BasedURL
                });
                chrome.storage.local.set({ history: history });
            });
            return;
        } else {
            console.log("URL в черном списке");
        }
    } catch (error) {
        console.error("Ошибка в функции обработчика вкладки:", error);
    }
}
