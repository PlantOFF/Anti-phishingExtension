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


// Вывод WhiteList
function WriteWhiteList(){
  chrome.storage.local.get({ whitelist: [] }, (result) => {
    const whitelist = result.whitelist || [];
    const whitelistContainer = document.getElementById('whitelistItems');
    whitelistContainer.innerHTML = '';
    whitelist.forEach((url) => {
      const li = document.createElement('li');
      li.textContent = url;
      whitelistContainer.appendChild(li);
    });
  });
};


// Добавление заблокированных сайтов
document.addEventListener('DOMContentLoaded', () => {
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
                  if (ans === "suspicious") {
                      suspicious += `${check_list}, `;
                  }
              }
              malicious = malicious.slice(0, -2);
              suspicious = suspicious.slice(0, -2);
          }
          const li = document.createElement('li');
          li.textContent =
              `[${item.time}] - 
              ${item.url} - 
              ${item.response[0]}, ${item.response[1]}, ${item.response[2]} - 
              malicious: ${malicious} 
              suspicious: ${suspicious}`;
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
    console.log(`Текущий URL: ${currentURL}`);
    let BasedURL = currentURL;
    currentURL = getBaseUrl(currentURL);
    console.log("Глобальный URL: " + currentURL);
    urlElement.innerHTML = currentURL;
    console.log(`Проверяемый URL: ${currentURL}`);

    chrome.storage.local.get({ history: [] }, (result) => {
      const history = result.history;
  
      if (history.length === 0) {
          safetyElement.innerHTML = "откройте вкладку для начала работы";
          return;
      }
      const lastCheck = history[history.length - 1];
      const HSstatsWtiteList = lastCheck.statsWtiteList;
      const HISsafetyResult = lastCheck.safetyResult;
      const HIScurrentURL = lastCheck.currentURL;
      const HISBasedURL = lastCheck.BasedURL;
  
      if (!HSstatsWtiteList) {
          if (HIScurrentURL === currentURL && HISBasedURL === BasedURL) {
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
  });  
}});


// White лист
document.getElementById("addWhitelistButton").addEventListener("click", () => {
  const url = document.getElementById("whitelistInput").value.trim();
  if (url) {
      chrome.storage.local.get("whitelist", (result) => {
        const whitelist = result.whitelist || [];
        if (!whitelist.includes(url)) {
          whitelist.push(url);
          chrome.storage.local.set({ whitelist }, () => {
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


// Настройка порогов проверки
// Настройка порогов проверки
document.getElementById('saveSettingsBtn').addEventListener('click', () => {
  const suspiciousInput = document.getElementById('suspiciousThreshold');
  const maliciousInput = document.getElementById('maliciousThreshold');

  const suspiciousThreshold = parseInt(suspiciousInput.value, 10);
  const maliciousThreshold = parseInt(maliciousInput.value, 10);

  if (isNaN(suspiciousThreshold) || isNaN(maliciousThreshold)) {
    console.warn('Введите корректные числовые значения.');
    return;
  }

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
