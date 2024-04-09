const GOVSSO_SESSION_UPDATE_BUFFER_SECONDS = 2 * 60;
const RETRY_BUFFER_SECONDS = 10;

var sessionLengthInSeconds;
var sessionTimer;
var timeout;
var endTime;

$(window).on('load', function() {
    var isChecked = localStorage.getItem('isChecked');

    if (isChecked == 'false') {
        $('#autoUpdate').prop('checked', false);
    } else {
        $('#autoUpdate').prop('checked', true);
    }

    $('#autoUpdate').change(function () {
        if($('#autoUpdate').is(':checked')){
            localStorage.setItem('isChecked', 'true');
        } else {
            localStorage.setItem('isChecked', 'false');
        }
    });
    $('#updateButton').click(updateGovSsoSession);

    sessionLengthInSeconds = +$('#updateTimer').text();
    endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds;
    timeout = setTimeout(autoUpdateGovSsoSession, sessionLengthInSeconds * 1000);
    sessionTimer = setInterval(incrementSeconds, 1000);
});

//TODO find a way to use leader election for browser tabs to prevent automatic session updates on multiple tabs
function updateGovSsoSession() {
    $('#updateButton').prop('disabled',true);
    const csrfToken = $('meta[name="_csrf"]').attr('content');
    const csrfHeader = $('meta[name="_csrf_header"]').attr('content');
    var scope = '';
    if ($('#scope').val()) {
        scope = '?scope=' + encodeURIComponent($('#scope').val());
    }
    (async () => {
        await fetch('/oauth2/refresh/govsso' + scope, {
            method: 'POST',
            headers: {
                [csrfHeader]: csrfToken,
            },
            redirect: 'manual'
        }).then(async function (response) {
            if (response.ok) {
                const responseBody = await response.json();
                const claimsTableBody = $('#claimsTableBody');
                const rows = [];

                $('#id_token').text(responseBody.id_token);
                $('#access_token').text(responseBody.access_token);
                $('#refresh_token').text(responseBody.refresh_token);

                $.each(responseBody.id_token_claims, function (key, value) {
                  const keyCell = $("<td></td>").text(key);
                  const valueCell = $("<td></td>").text(value);
                  rows.push($("<tr></tr>").append([keyCell, valueCell]));
                });
                $('#claimsTableBody').html(rows);
                $('#error').hide();

                sessionLengthInSeconds = responseBody.time_until_govsso_session_expiration_in_seconds;
                clearInterval(sessionTimer);
                endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS;
                sessionTimer = setInterval(incrementSeconds, 1000);
                clearTimeout(timeout);
                timeout = setTimeout(autoUpdateGovSsoSession, (sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS) * 1000);

                $('#error').hide();
                $('#updateButton').prop('disabled',false);
            } else {
                $('#error').show();
                $('#error').text('Error updating GovSSO session. Refresh token is expired.');
                clearTimeout(timeout);
                $('#updateButton').prop('disabled',false);
            }
        }).catch((error) => {
            $('#error').show();
            $('#error').text('Error updating GovSSO session: ' + error.message + ' Retrying.');
            $('#updateButton').prop('disabled',false);
            clearTimeout(timeout);
            timeout = setTimeout(autoUpdateGovSsoSession, RETRY_BUFFER_SECONDS * 1000);
        });
    })();
}

function incrementSeconds() {
    var timeUntilSessionUpdateInSeconds = endTime - getCurrentTimeStampInSeconds();

    if (timeUntilSessionUpdateInSeconds >= 0) {
        $('#updateTimer').text(timeUntilSessionUpdateInSeconds);
    } else {
        clearInterval(sessionTimer);
    }
}

function autoUpdateGovSsoSession() {
    if($('#autoUpdate').prop('checked')) {
        updateGovSsoSession();
    }
}

function getCurrentTimeStampInSeconds() {
    return Math.floor(Date.now() / 1000);
}
