let secondsUntilLocalSessionExpiration;
let timer;

window.addEventListener('load', function() {
    secondsUntilLocalSessionExpiration = Number.parseInt(document.getElementById('idleTimer').textContent, 10);
    timer = setInterval(decrementTimeUntilSessionExpiration, 1000);
});

const decrementTimeUntilSessionExpiration = function() {
    secondsUntilLocalSessionExpiration -= 1;
    if (secondsUntilLocalSessionExpiration <= 0) {
        //TODO: Redirect to logout?
        clearInterval(timer);
    }
    document.getElementById('idleTimer').textContent = secondsUntilLocalSessionExpiration;
};
