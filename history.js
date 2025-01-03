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
