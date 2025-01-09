const urlElement = document.getElementById("URL");
const safetyElement = document.getElementById("safety");
const openHistoryButton = document.getElementById("open-history");
const inputWhiteList = document.getElementById("input_white_list");
const contentWhiteList = document.getElementById("content_white_list");
const WhiteListURL = document.getElementById("open-white-list");

// 1 - 5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a
// 2 - cd87ccaf0717dec26cdb5aef31d5468323f915836465dd49bed358233ef45239
const apiKey = "5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a";
const apiUrl = "https://www.virustotal.com/api/v3/urls";

var black_list = ["chrome://extensions/", "about:blank", "chrome://newtab/",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/blockURL.html",
    "chrome-extension://kloheonpepgpngbdmgechkckdbilbioo/html/history.html",
    "chrome-extension://inlnholhelnepdinmgbennhcjpbokbmg/html/history.html"
];


// Проверка наличия в черном листе
function CheckBlackList(url){
    for (var i = 0; i < black_list.length; i++){
        if (url === black_list[i]){
            return false;
    }};
    console.log("URL нет в черном списке")
    return true;
};


// Получение глобального URL
function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};


// Функция кодирования URL
function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
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
        };
        if (response.status === 429) {
            console.log("Слишком много попыток");
            return null;
        };

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;

        return [stats.harmless, stats.suspicious, stats.malicious];
    } catch (error) {
        console.log("Ошибка на стороне расширения (ответ от API не получен)");
        return null;
    }
}


// Добавление заблокированных сайтов
document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const list = document.getElementById('blocked-list');
        result.blocked.forEach(item => {
            const li = document.createElement('li');
            li.textContent = `[${item.time}] - ${item.url}`;
            list.appendChild(li);
        });
    });
});



// Переключение вкладок
document.addEventListener("DOMContentLoaded", () => {
    const tabButtons = document.querySelectorAll(".tab-button");
    const tabContents = document.querySelectorAll(".tab-content");

    tabButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const targetTab = button.getAttribute("data-tab");

            // Удаляем активный класс со всех кнопок и вкладок
            tabButtons.forEach((btn) => btn.classList.remove("active"));
            tabContents.forEach((content) => content.classList.remove("active"));

            // Добавляем активный класс на выбранную кнопку и вкладку
            button.classList.add("active");
            document.getElementById(targetTab).classList.add("active");
        });
    });
});



// Основная логика
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {{
        let currentURL = tabs[0].url;
        urlElement.textContent = `${currentURL}`;
        console.log(`Текущий URL: ${currentURL}`);
        let BasedURL = currentURL;
        currentURL = getBaseUrl(currentURL);
        console.log("Глобальный URL: " + currentURL)
        urlElement.innerHTML += "<br>" + currentURL;
        console.log(`Проверяемый URL: ${currentURL}`);
        if (CheckBlackList(currentURL) && CheckBlackList(BasedURL)){
            safetyResult = await checkUrlSafety(currentURL);
            if (safetyResult) {
                console.log(`Получен ответ:\n Безопасные: ${safetyResult[0]}\n Подозрительные: ${safetyResult[1]}\n Опасные: ${safetyResult[2]}`)
                safetyElement.innerHTML = `
                    Безопасные: ${safetyResult[0]} <br>
                    Подозрительные: ${safetyResult[1]} <br>
                    Опасные: ${safetyResult[2]}
                `;

                if (safetyResult[2] > 2 || safetyResult[1] > 2) {
                    chrome.storage.local.get({ blocked: [] }, (result) => {
                        let blocked = result.blocked;
                        blocked.push({ url: currentURL, time: new Date().toLocaleString() });
                        chrome.storage.local.set({ blocked: blocked });
                    });
                    chrome.tabs.update(tabs[0].id, { url: 'html/blockURL.html' });
                    console.log('URL подозрителен или опасен, вкладка заменена.');
                }

            }
            else{
                safetyElement.innerHTML = "Вероятно такого url нет в базе"
                console.log("Вероятно такого url нет в базе")
            }
        }
        else{
            safetyElement.innerHTML = "URL находится в черном списке"
            console.log("URL находится в черном списке")
        }
}});

// White лист
document.getElementById('addWhitelistButton').addEventListener('click', () => {
    const url = document.getElementById('whitelistInput').value.trim();
    if (url) {
        chrome.runtime.sendMessage({ action: 'addToWhitelist', url }, (response) => {
            if (response.success) {
                console.log(`URL успешно добавлен: ${url}`);
                black_list.push(url)
            } 
            else {
                console.error('Ошибка:', response.error);
            }
        });
    } else {
        console.log("пустое поле ввода");
    }
});
