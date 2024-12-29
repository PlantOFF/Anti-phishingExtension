const urlElement = document.getElementById("URL");
const safetyElement = document.getElementById("safety");

// 1 - 5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a
// 2 - cd87ccaf0717dec26cdb5aef31d5468323f915836465dd49bed358233ef45239
const apiKey = "5272220c5a9335749c17741babbc8bc54f48ace689f5a29b1c5653ca68068e4a";
const apiUrl = "https://www.virustotal.com/api/v3/urls";

let whiteList = [];
const inputWhiteList = document.getElementById("input_white_list");
const contentWhiteList = document.getElementById("content_white_list");


// Функция сокращения url
function ShortURL(url) {
    const lastIndex = url.lastIndexOf('/');
    if (lastIndex > 0) {
        return url.slice(0, lastIndex);
    }
    return url;
}

// Функция кодирования URL
function encodeUrl(url) {
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


// Проверка безопасности URL
async function checkUrlSafety(url) {
    try {
        const encodedUrl = encodeUrl(url);
        console.log(`Кодированный URL: ${encodedUrl}`);
        const response = await fetch(`${apiUrl}/${encodedUrl}`, {
            method: "GET",
            headers: {
                "x-apikey": apiKey,
            },
        });

        if (response.status === 404) {
            console.log("Ошибка (404 от API)\n Вероятно, такого сайта нет в базе");
            console.log(`HTTP статус ответа: ${response.status}`);
            return null;
        }
        
        if (response.status === 429) {
            safetyElement.textContent = "Слишком много запросов. Попробуйте позже. (429)";
            console.error(`HTTP статус ответа: ${response.status}`);
            return null;
        }
        else {
            console.log(`HTTP статус ответа: ${response.status}`);
        }

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;

        return [stats.harmless, stats.suspicious, stats.malicious];
    } catch (error) {
        console.error(`Ошибка проверки URL`);
        safetyElement.textContent = "Ошибка при проверке URL. Попробуйте снова.";
        return null;
    }
}


// Основная логика
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {{
        let currentURL = tabs[0].url;
        urlElement.textContent = `${currentURL}`;
        console.log(`Текущий URL: ${currentURL}`);
        let urlLength = currentURL.length;

        while (urlLength >= 8){
            console.log(`Проверяемый URL: ${currentURL}`);
            try{
                          
                safetyResult = await checkUrlSafety(currentURL);

                if (safetyResult) {
                    console.log(`Получен ответ:\n Безопасные: ${safetyResult[0]}\n Подозрительные: ${safetyResult[1]}\n Опасные: ${safetyResult[2]}`)
                    safetyElement.innerHTML = `
                        Безопасные: ${safetyResult[0]} <br>
                        Подозрительные: ${safetyResult[1]} <br>
                        Опасные: ${safetyResult[2]}
                    `;
                    
                    if (safetyResult[2] > 0 || safetyResult[1] > 0) {
                        chrome.tabs.update(tabs[0].id, { url: 'html/blockURL.html' });
                        console.log('URL подозрителен или опасен, вкладка заменена.');
                    }
                    
                    return;
                } 
                else {
                    currentURL = ShortURL(currentURL);
                    urlLength = currentURL.length;
                }
            }
            catch (error) {
                console.error("URL не удалось проверить");
            }
        }
        safetyElement.innerHTML = "Вероятно такого url нет в базе"
}});
