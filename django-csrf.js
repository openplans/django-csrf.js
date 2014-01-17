/*global jQuery */

/*****************************************************************************

CSRF Validation
---------------
Django protects against Cross Site Request Forgeries (CSRF) by default. This
type of attack occurs when a malicious Web site contains a link, a form button
or some javascript that is intended to perform some action on your Web site,
using the credentials of a logged-in user who visits the malicious site in their
browser.

Since the API proxy view sends requests that write data to the Shareabouts
service authenticated as the owner of this dataset, we want to protect the API
view against CSRF. In order to ensure that AJAX POST/PUT/DELETE requests that
are made via jQuery will not be caught by the CSRF protection, we use the
following code. For more information, see:
https://docs.djangoproject.com/en/1.6/ref/contrib/csrf/
*/

jQuery(function() {
  function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      var cookies = document.cookie.split(';');
      for (var i = 0; i < cookies.length; i++) {
        var cookie = jQuery.trim(cookies[i]);
        // Does this cookie string begin with the name we want?
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }

  function safeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
  }

  jQuery.ajaxSetup({
    crossDomain: false, // obviates need for sameOrigin test
    beforeSend: function(xhr, settings) {
      if (!safeMethod(settings.type)) {
        xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
      }

      // If this is a DELETE request, explicitly set the data to be sent so that
      // the browser will calculate a value for the Content-Length header.
      if (settings.type === 'DELETE') {
        xhr.setRequestHeader("Content-Type", "application/json");
        settings.data = '{}';
      }
    }
  });
});
