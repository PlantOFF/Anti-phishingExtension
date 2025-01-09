const urlElement = document.getElementById("URL");
const safetyElement = document.getElementById("safety");

const apiKey = "5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a";
const apiUrl = "https://www.virustotal.com/api/v3/urls";

function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


// ПРОВЕРКА URL
async function checkUrlSafety(url) {
    const encodedUrl = encodeUrl(url);
    logMessage(`Кодированный URL: ${encodedUrl}`);

    try {
        const response = await fetch(`${apiUrl}/${encodedUrl}`, {
            method: "GET",
            headers: {
                "x-apikey": apiKey,
            },
        });

        logMessage(`HTTP статус ответа: ${response.status}`);

        const data = await response.json();
        logMessage(`Ответ API: ${JSON.stringify(data)}`);

        const stats = data.data.attributes.last_analysis_stats;

        return [stats.harmless, stats.suspicious, stats.malicious];

    } catch (error) {
        if (url.includes('/')) {
            url = url.slice(0, url.lastIndexOf('/'));
            logMessage(`Сокращенный URL: ${url}`);
        } else {
            logMessage("URL не удалось сократить дальше.");
        }
        return [0, 0, 0];
    }
}


// ЛОГИ
function logMessage(message) {
    const logsElement = document.getElementById("logs_content");
    message = message.replace(/\n/g, '<br>')
    message = `${JSON.stringify(message, null, 2)}`;
    logsElement.innerHTML += `${message}<br>`;
}


// ОТКРЫАЯ ВКЛАДКА
chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
    if (tabs.length > 0) {
        const currentURL = tabs[0].url;
        urlElement.textContent = `${currentURL}`;

        const safetyResult = await checkUrlSafety(currentURL);
        if (safetyResult) {
            safetyElement.innerHTML = `Безопастные: ${safetyResult[0]} <br> Подозрительные: ${safetyResult[1]} <br> Опасные: ${safetyResult[2]}`;
            if (safetyResult[2] > 0) {
                chrome.tabs.update(tabs[0].id, {url: 'html/blockURL.html'});
                logMessage('URL опасен, вкладка заменена на пустую.');
                return;
            }
        } else {
            safetyElement.innerHTML = "Проверка завершилась без результата.";
        }
        logMessage(`Результат проверки:\n${safetyResult}`);
    } else {
        urlElement.textContent = "Не удалось получить текущий URL.";
        safetyElement.textContent = "Проверка невозможна.";
        logMessage("Не удалось получить текущий URL.");
    }
});


// КНОПКА ДЛЯ ЛОГОВ

const toggleButton = document.getElementById("logs_Button");
const logsContainer = document.getElementById("logs");

toggleButton.addEventListener("click", function () {
    if (logsContainer.style.display === "") {
        toggleButton.textContent = "Скрыть";
        logsContainer.style.display = "block";
    } else if (logsContainer.style.display === "block") {
        toggleButton.textContent = "Отобразить";
        logsContainer.style.display = "";
    }
});
