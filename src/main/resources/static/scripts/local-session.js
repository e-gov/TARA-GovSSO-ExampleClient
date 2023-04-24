let secondsUntilLocalSessionExpiration;
let timer;

$(window).on('load', function() {
    secondsUntilLocalSessionExpiration = +$('#idleTimer').text();
    timer = setInterval(decrementTimeUntilSessionExpiration, 1000);
});

const decrementTimeUntilSessionExpiration = function() {
    secondsUntilLocalSessionExpiration -= 1;
    if (secondsUntilLocalSessionExpiration <= 0) {
        //TODO: Redirect to logout?
        clearInterval(timer);
    }
    $('#idleTimer').text(secondsUntilLocalSessionExpiration);
}
