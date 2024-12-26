const urlElement = document.getElementById("URL");
const safetyElement = document.getElementById("safety");

const apiKey = "5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a";
const apiUrl = "https://www.virustotal.com/api/v3/urls";

function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


// ОТКРЫАЯ ВКЛАДКА
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (tabs.length > 0) {
        const currentURL = tabs[0].url;
        urlElement.textContent = `${currentURL}`;

        const safetyResult = await checkUrlSafety(currentURL);
        if (safetyResult.slice(0, -1) === "Проверка завершилась без результата") {
            var print_safetyResult = safetyResult
        }
        else{
            var print_safetyResult = "- Безопасные: " + safetyResult[0] + "\n" + 
            "- Подозрительные: " + safetyResult[1] + "\n" + 
            "- Опасные: " + safetyResult[2] + "\n";
        }

        safetyElement.innerHTML = print_safetyResult.replace(/\n/g, '<br>');
        logMessage(`Результат проверки:\n${print_safetyResult}`);

        if (safetyResult[2] > 0) {
                chrome.tabs.update(tabs[0].id, {url: 'html/blockURL.html'});
                logMessage('URL опасен, вкладка заменена на пустую.');
            }
        
        if (safetyResult[2] >= 2) {
            chrome.tabs.update({ url: 'BlockURL.html' });
        }
    } 
    else {
        urlElement.textContent = "Не удалось получить текущий URL.";
        safetyElement.textContent = "Проверка невозможна.";
        logMessage("Не удалось получить текущий URL.");
        if (safetyResult[0] === "П") {
            urlElement.textContent = "Не удалось получить текущий URL."

        }
    }
});


// ПРОВЕРКА URL
async function checkUrlSafety(url) {
    while (url.length != 0) {

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
        } 
        catch (error) {
            if (url.includes('/')) {
                url = url.slice(0, url.lastIndexOf('/'));
                logMessage(`Сокращенный URL: ${url}`);
            } else {
                logMessage("URL не удалось сократить дальше.");
                break;
            }
        }
    }
    return "Проверка завершилась без результата.";
}


// ЛОГИ
function logMessage(message) {
    const logsElement = document.getElementById("logs_content");
    message = message.replace(/\n/g, '<br>')
    message = `${JSON.stringify(message, null, 2)}`;
    logsElement.innerHTML += `${message}<br>`;
}   


// КНОПКА ДЛЯ ЛОГОВ
const toggleButton = document.getElementById("logs_Button");
const logsContainer = document.getElementById("logs");

toggleButton.addEventListener("click", function() {
    if (logsContainer.style.display === "") {
        toggleButton.textContent = "Скрыть";
        logsContainer.style.display = "block";
    }
    else if (logsContainer.style.display === "block") {
        toggleButton.textContent = "Отобразить";
        logsContainer.style.display = "";
    }
});

// ДОБАВЛЕНИЕ В БЕЛЫЙ СПИСОК
const button_white_list = document.getElementById("white_list");
const input_white_list = document.getElementById("input_white_list")
button_white_list.addEventListener("click", function() {
    if (input_white_list.style.display === "") {
        button_white_list.textContent = "Скрыть белый список";
        input_white_list.style.display = "block";
    }
    else if (input_white_list.style.display === "block") {
        button_white_list.textContent = "Открыть белый список";
        input_white_list.style.display = "";
    }
});

var white_list = [];
