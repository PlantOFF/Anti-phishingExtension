const urlElement = document.getElementById("URL");
const safetyElement = document.getElementById("safety");
const openHistoryButton = document.getElementById("open-history");
const inputWhiteList = document.getElementById("input_white_list");
const contentWhiteList = document.getElementById("content_white_list");
const WhiteListURL = document.getElementById("open-white-list");


// Получение глобального URL
function getBaseUrl(url) {
    const parsedUrl = new URL(url);
    return `${parsedUrl.protocol}//${parsedUrl.host}`;
};


// Вывод WhiteList с кнопкой удаления
function WriteWhiteList() {
    chrome.storage.local.get({whitelist: []}, (result) => {
        const whitelist = result.whitelist || [];
        const whitelistContainer = document.getElementById('whitelistItems');
        whitelistContainer.innerHTML = ''; // Очищаем контейнер перед обновлением

        // Обновляем текст кнопки в зависимости от наличиства элементов
        const toggleButton = document.getElementById('toggleWhitelistButton');
        toggleButton.disabled = whitelist.length === 0;

        whitelist.forEach((url) => {
            const li = document.createElement('li');
            li.style.display = 'flex';
            li.style.alignItems = 'center';
            li.style.justifyContent = 'space-between';

            // Текст с URL
            const urlText = document.createElement('span');
            urlText.textContent = url;
            li.appendChild(urlText);

            // Кнопка удаления
            const deleteButton = document.createElement('button');
            deleteButton.textContent = '×'; // Крестик
            deleteButton.style.marginLeft = '10px';
            deleteButton.style.cursor = 'pointer';
            deleteButton.style.background = 'none';
            deleteButton.style.border = 'none';
            deleteButton.style.color = 'red';
            deleteButton.style.fontSize = '16px';

            // Обработчик удаления URL
            deleteButton.addEventListener('click', () => {
                removeFromWhitelist(url);
            });

            li.appendChild(deleteButton);
            whitelistContainer.appendChild(li);
        });
    });
}

// Показать/скрыть весь WhiteList
document.getElementById("toggleWhitelistButton").addEventListener("click", () => {
    const list = document.getElementById("whitelistItems");
    const button = document.getElementById("toggleWhitelistButton");
    
    if (list.style.display === "none") {
        list.style.display = "block";
        button.textContent = "Скрыть список";
        WriteWhiteList(); // Обновляем список при открытии
    } else {
        list.style.display = "none";
        button.textContent = "Показать список";
    }
});

// Функция для удаления URL из whitelist
function removeFromWhitelist(url) {
    chrome.storage.local.get({whitelist: []}, (result) => {
        const whitelist = result.whitelist || [];
        const updatedWhitelist = whitelist.filter(item => item !== url); // Удаляем URL из массива

        // Сохраняем обновленный whitelist
        chrome.storage.local.set({whitelist: updatedWhitelist}, () => {
            console.log(`URL ${url} удален из whitelist.`);
            WriteWhiteList(); // Обновляем отображение whitelist
        });
    });
}


document.addEventListener('DOMContentLoaded', () => {
    const history_data = []; // Глобальный массив для хранения данных

    chrome.storage.local.get({ blocked: [] }, (result) => {
        const list = document.getElementById('blocked-list');

        result.blocked.forEach(item => {
            const DetailedResult = item.DetailedResult || [];
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

            const li = document.createElement('li');
            li.textContent =
                `[${item.time}] - 
              ${item.ALLURL} - 
              ${item.response[0]}, ${item.response[1]}, ${item.response[2]} - 
              Опасный: ${malicious} 
              Подозрительный: ${suspicious}`;
            list.appendChild(li);

            // Добавляем данные в массив history_data
            history_data.push({
                date: item.time,
                url: item.ALLURL,
                ans: `${item.response[0]}, ${item.response[1]}, ${item.response[2]}`,
                malicious: malicious,
                suspicious: suspicious
            });
        });

        console.log(history_data); // Проверяем, что данные собраны корректно
    });

    // Обработчик кнопки "Скачать данные"
    document.getElementById('downloadDataButton').addEventListener('click', () => {
        const format = document.getElementById('exportFormat').value;

        // Проверяем, что массив history_data не пустой
        if (history_data.length === 0) {
            alert('Нет данных для экспорта.');
            return;
        }

        if (format === 'csv') {
            // Преобразуем данные в CSV
            const csvData = convertToCSV(history_data);
            downloadFile(csvData, 'blocked_sites.csv', 'text/csv;charset=utf-8;');
        } else if (format === 'json') {
            // Преобразуем данные в JSON
            const jsonData = JSON.stringify(history_data, null, 2);
            downloadFile(jsonData, 'blocked_sites.json', 'application/json;charset=utf-8;');
        }
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
chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
    {
        let currentURL = tabs[0].url;
        console.log(`Текущий URL: ${currentURL}`);
        let ALLURL = currentURL;
        currentURL = getBaseUrl(currentURL);
        console.log("Глобальный URL: " + currentURL);
        urlElement.innerHTML = currentURL;
        console.log(`Проверяемый URL: ${currentURL}`);

        if (currentURL === "chrome-extension://foigjkpkfbdhgakepeblljommemkolbo"){
            safetyElement.innerHTML = "Открыта страница блокировки";
            return;
        };
        chrome.storage.local.get({history: []}, (result) => {
            const history = result.history;

            if (history.length === 0) {
                safetyElement.innerHTML = "откройте сайт для начала работы";
                return;
            }
            try{
            const lastCheck = history[history.length - 1];
            const HSstatsWtiteList = lastCheck.statsWtiteList;
            const HISsafetyResult = lastCheck.safetyResult;
            const HIScurrentURL = lastCheck.currentURL;
            const HISALLURL = lastCheck.ALLURL;

            if (!HSstatsWtiteList) {
                if (HIScurrentURL === currentURL && HISALLURL === ALLURL) {
                    safetyElement.innerHTML = `
                  Безопасные: ${HISsafetyResult[0]} <br>
                  Подозрительные: ${HISsafetyResult[1]} <br>
                  Опасные: ${HISsafetyResult[2]}
              `;
                } else {
                    safetyElement.innerHTML = "откройте вкладку для начала работы";
                }
            } else {
                safetyElement.innerHTML =
                    "URL находится в white list или скрыт по умолчанию";
            }
            } catch{
                safetyElement.innerHTML = "откройте сайт для начала работы";
            }
        });
    };
});


// White лист
document.getElementById("addWhitelistButton").addEventListener("click", () => {
    const url = document.getElementById("whitelistInput").value.trim();
    if (url) {
        chrome.storage.local.get("whitelist", (result) => {
            const whitelist = result.whitelist || [];
            if (!whitelist.includes(url)) {
                whitelist.push(url);
                chrome.storage.local.set({whitelist}, () => {
                    console.log(`URL ${url} добавлен в whitelist.`);
                    document.getElementById("whitelistInput").value = ""
                    WriteWhiteList()
                });
            } else {
                console.log(`URL ${url} уже существует в whitelist.`);
                document.getElementById("whitelistInput").value = ""
            }
        });
    } else {
        console.log("пустое поле ввода");
    }
});


// Фильтр по истории блокировок
document.addEventListener('DOMContentLoaded', () => {
    // Функция для обновления списка баз данных
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const blocked = result.blocked;
        const filterBases = document.getElementById("filterBases");
        const uniqueBases = new Set();

        blocked.forEach(item => {
            const DetailedResult = item.DetailedResult || [];
            DetailedResult.forEach(result => {
                const [base, status] = result.split(": ");
                if (status === "malicious" || status === "suspicious") {
                    uniqueBases.add(base.trim());
                }
            });
        });

        // Очищаем select перед добавлением новых значений
        filterBases.innerHTML = '<option value="">Все базы данных</option>';
        uniqueBases.forEach(base => {
            const option = document.createElement("option");
            option.value = base;
            option.textContent = base;
            filterBases.appendChild(option);
        });
    });

    // Функция для обновления списка доменов
    chrome.storage.local.get({ blocked: [] }, (result) => {
        const blocked = result.blocked;
        const filterDomains = document.getElementById("filterBlockedSites");
        const uniqueDomains = new Set();

        filterDomains.innerHTML = '<option value="">Все домены</option>';

        blocked.forEach(item => {
            try {
                const url = new URL(item.ALLURL);
                const domain = `${url.hostname}`; // Извлекаем только hostname без протокола
                uniqueDomains.add(domain);
            } catch (e) {
                console.warn(`Неверный URL: ${item.ALLURL}`);
            }
        });

        uniqueDomains.forEach(domain => {
            const option = document.createElement("option");
            option.value = domain;
            option.textContent = domain;
            filterDomains.appendChild(option);
        });
    });

    // Обработчик кнопки "Применить"
    document.getElementById("showFilteredHistoryBtn").addEventListener("click", () => {
        const selectedBase = document.getElementById("filterBases").value;
        const selectedDomain = document.getElementById("filterBlockedSites").value;
        const startDateValue = document.getElementById("startDate").value;
        const endDateValue = document.getElementById("endDate").value;
        const list = document.getElementById("blocked-list");

        list.innerHTML = ""; // Очищаем список перед добавлением новых записей

        chrome.storage.local.get({ blocked: [] }, (result) => {
            const blocked = result.blocked;
            const uniqueEntries = new Set();

            blocked.forEach(item => {
                let includeItem = true;
                let malicious = "";
                let suspicious = "";

                // Проверка домена
                let itemDomain = "";
                try {
                    const url = new URL(item.ALLURL);
                    itemDomain = url.hostname;
                    if (selectedDomain && itemDomain !== selectedDomain) {
                        includeItem = false; // Если выбранный домен не совпадает — исключаем запись
                    }
                } catch (e) {
                    console.warn(`Неверный URL: ${item.ALLURL}`);
                    includeItem = false;
                }

                // Проверка базы данных
                let baseMatch = !selectedBase; // Если база не выбрана, пропускаем проверку
                const DetailedResult = item.DetailedResult || [];
                DetailedResult.forEach(result => {
                    const [base, status] = result.split(": ");
                    if (status === "malicious") {
                        malicious += `${base}, `;
                    }
                    if (status === "suspicious") {
                        suspicious += `${base}, `;
                    }
                    if (base === selectedBase) {
                        baseMatch = true;
                    }
                });

                // Очистка запятых в строках
                malicious = malicious.slice(0, -2) || "Нет";
                suspicious = suspicious.slice(0, -2) || "Нет";

                // Проверка даты
                const recordTime = new Date(item.time);
                const startDate = startDateValue ? new Date(startDateValue) : null;
                const endDate = endDateValue ? new Date(endDateValue + 'T23:59:59') : null;

                const isAfterStartDate = !startDate || recordTime >= startDate;
                const isBeforeEndDate = !endDate || recordTime <= endDate;

                // Если запись соответствует всем условиям, добавляем её в список
                if (includeItem && baseMatch && isAfterStartDate && isBeforeEndDate) {
                    if (!uniqueEntries.has(item.time)) {
                        uniqueEntries.add(item.time);
                        const li = document.createElement("li");
                        li.textContent =
                            `[${item.time}] - 
                            ${item.ALLURL} - 
                            ${item.response[0]}, ${item.response[1]}, ${item.response[2]} - 
                            Опасный: ${malicious}  
                            Подозрительный: ${suspicious}`;
                        list.appendChild(li);
                    }
                }
            });
        });
    });
});


// Добавление функционала вкладки "Настройки"
document.getElementById('saveSettingsButton').addEventListener('click', () => {
    const suspiciousInput = document.getElementById('settingsSuspiciousThreshold');
    const maliciousInput = document.getElementById('settingsMaliciousThreshold');

    const suspiciousThreshold = parseInt(suspiciousInput.value, 10);
    const maliciousThreshold = parseInt(maliciousInput.value, 10);

    // Проверка на отрицательные значения
    if (isNaN(suspiciousThreshold) || suspiciousThreshold < 0) {
        console.warn('Подозрительный порог должен быть неотрицательным числом.');
        alert('Введите неотрицательное значение для подозрительного порога.');
        return;
    }
    if (isNaN(maliciousThreshold) || maliciousThreshold < 0) {
        console.warn('Опасный порог должен быть неотрицательным числом.');
        alert('Введите неотрицательное значение для опасного порога.');
        return;
    }

    // Сохраняем настройки в локальное хранилище
    chrome.storage.local.set({
        thresholds: {
            suspicious: suspiciousThreshold,
            malicious: maliciousThreshold,
        },
    }, () => {
        console.log(`Сохранены пороги: suspicious = ${suspiciousThreshold}, malicious = ${maliciousThreshold}`);
    });

    suspiciousInput.value = '';
    maliciousInput.value = '';
});

function convertToCSV(data) {
    const csvRows = [];
    
    // Заголовки таблицы
    const headers = Object.keys(data[0]);
    csvRows.push(headers.join(',')); // Разделяем заголовки запятыми

    // Добавляем строки данных
    for (const row of data) {
        const values = headers.map(header => {
            let value = row[header];
            if (typeof value === 'string') {
                // Экранируем кавычки и запятые внутри строковых значений
                value = value.replace(/"/g, '""');
                if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                    value = `"${value}"`;
                }
            } else {
                value = String(value);
            }
            return value;
        });
        csvRows.push(values.join(','));
    }

    return csvRows.join('\n'); // Разделяем строки символом новой строки
}

function downloadFile(data, filename, mimeType) {
    const blob = new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

// Очистка истории
document.getElementById('clearHistoryButton').addEventListener('click', () => {
    chrome.storage.local.set({ blocked: [] }, () => {
        console.log("История очищена.");
        const list = document.getElementById('blocked-list');
        list.innerHTML = "";
    });
});