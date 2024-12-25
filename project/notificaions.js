function addToWhitelist() {
    if (Notification.permission === "granted") {
        // Пользователь дал разрешение на уведомления
        new Notification("Вы получили новое сообщение!");
    } else if (Notification.permission !== "denied") {
        // Запрашиваем разрешение на отправку уведомлений
        Notification.requestPermission(permission => {
            if (permission === "granted") {
                new Notification("Вы получили новое сообщение!");
            }
        });
    }
}
