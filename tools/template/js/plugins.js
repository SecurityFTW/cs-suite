// Avoid `console` errors in browsers that lack a console.
(function() {
    var method;
    var noop = function () {};
    var methods = [
        'assert', 'clear', 'count', 'debug', 'dir', 'dirxml', 'error',
        'exception', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log',
        'markTimeline', 'profile', 'profileEnd', 'table', 'time', 'timeEnd',
        'timeline', 'timelineEnd', 'timeStamp', 'trace', 'warn'
    ];
    var length = methods.length;
    var console = (window.console = window.console || {});

    while (length--) {
        method = methods[length];

        // Only stub undefined methods.
        if (!console[method]) {
            console[method] = noop;
        }
    }
}());

// Place any jQuery/helper plugins in here.
var win_w = window.innerWidth;
var win_h = $(window).height();

var UP = 38;
var DOWN = 40;
var LEFT = 37;
var RIGHT = 39;
var ESC = 27;
var ENTER = 13;


$(window).resize(function(){
    win_w = window.innerWidth;
    win_h = $(window).height();

});
(function(global) {

    var apple_phone = /iPhone/i,
        apple_ipod = /iPod/i,
        apple_tablet = /iPad/i,
        android_phone = /(?=.*\bAndroid\b)(?=.*\bMobile\b)/i,
        android_tablet = /Android/i,
        windows_phone = /IEMobile/i,
        windows_tablet = /(?=.*\bWindows\b)(?=.*\bARM\b)/i,
        other_blackberry = /BlackBerry/i,
        other_blackberry_10 = /BB10/i,
        other_opera = /Opera Mini/i,
        other_firefox = /(?=.*\bFirefox\b)(?=.*\bMobile\b)/i,
        seven_inch = new RegExp('(?:' + 'Nexus 7' + '|' + 'BNTV250' + '|' + 'Kindle Fire' + '|' + 'Silk' + '|' + 'GT-P1000' + ')', 'i');
    var match = function(regex, userAgent) {
        return regex.test(userAgent);
    };
    var IsMobileClass = function(userAgent) {
        var ua = userAgent || navigator.userAgent;

        this.apple = {
            phone: match(apple_phone, ua),
            ipod: match(apple_ipod, ua),
            tablet: match(apple_tablet, ua),
            device: match(apple_phone, ua) || match(apple_ipod, ua) || match(apple_tablet, ua)
        };
        this.android = {
            phone: match(android_phone, ua),
            tablet: !match(android_phone, ua) && match(android_tablet, ua),
            device: match(android_phone, ua) || match(android_tablet, ua)
        };
        this.windows = {
            phone: match(windows_phone, ua),
            tablet: match(windows_tablet, ua),
            device: match(windows_phone, ua) || match(windows_tablet, ua)
        };
        this.other = {
            blackberry: match(other_blackberry, ua),
            blackberry10: match(other_blackberry_10, ua),
            opera: match(other_opera, ua),
            firefox: match(other_firefox, ua),
            device: match(other_blackberry, ua) || match(other_blackberry_10, ua) || match(other_opera, ua) || match(other_firefox, ua)
        };
        this.seven_inch = match(seven_inch, ua);
        this.any = this.apple.device || this.android.device || this.windows.device || this.other.device || this.seven_inch;
        this.phone = this.apple.phone || this.android.phone || this.windows.phone;
        this.tablet = this.apple.tablet || this.android.tablet || this.windows.tablet;
        if (typeof window === 'undefined') {
            return this;
        }
    };
    var instantiate = function() {
        var IM = new IsMobileClass();
        IM.Class = IsMobileClass;

        return IM;
    };
    if (typeof module != 'undefined' && module.exports && typeof window === 'undefined') {
        module.exports = IsMobileClass;
    } else if (typeof module != 'undefined' && module.exports && typeof window !== 'undefined') {
        module.exports = instantiate();
    } else if (typeof define === 'function' && define.amd) {
        define(global.isMobile = instantiate());
    } else {
        global.isMobile = instantiate();

    }
})(this);

console.log(isMobile.any);


// copyright 1999 Idocs, Inc. http://www.idocs.com
// Distribute this script freely but keep this notice in place
function numbersonly(myfield, e, dec) {
    var key;
    var keychar;

    if (window.event)
        key = window.event.keyCode;
    else if (e)
        key = e.which;
    else
        return true;
    keychar = String.fromCharCode(key);

    // control keys
    if ((key == null) || (key == 0) || (key == 8) ||
        (key == 9) || (key == 13) || (key == 27))
        return true;

    // numbers
    else if ((("+0123456789").indexOf(keychar) > -1))
        return true;

    // decimal point jump
    else if (dec && (keychar == ".")) {
        myfield.form.elements[dec].focus();
        return false;
    } else
        return false;
}

//https://gist.github.com/engelfrost/fd707819658f72b42f55
// Fake localStorage implementation. 
// Mimics localStorage, including events. 
// It will work just like localStorage, except for the persistant storage part. 

var fakeLocalStorage = function() {
    console.log("inside fakeLocalStorage");
  var fakeLocalStorage = {};
  var storage; 
  
  // If Storage exists we modify it to write to our fakeLocalStorage object instead. 
  // If Storage does not exist we create an empty object. 
  if (window.Storage && window.localStorage) {
    storage = window.Storage.prototype; 
  } else {
    // We don't bother implementing a fake Storage object
    window.localStorage = {}; 
    storage = window.localStorage; 
  }
  
  // For older IE
  if (!window.location.origin) {
    window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
  }

  var dispatchStorageEvent = function(key, newValue) {
    var oldValue = (key == null) ? null : storage.getItem(key); // `==` to match both null and undefined
    var url = location.href.substr(location.origin.length);
    var storageEvent = document.createEvent('StorageEvent'); // For IE, http://stackoverflow.com/a/25514935/1214183

    storageEvent.initStorageEvent('storage', false, false, key, oldValue, newValue, url, null);
    window.dispatchEvent(storageEvent);
  };

  storage.key = function(i) {
    var key = Object.keys(fakeLocalStorage)[i];
    return typeof key === 'string' ? key : null;
  };

  storage.getItem = function(key) {
    return typeof fakeLocalStorage[key] === 'string' ? fakeLocalStorage[key] : null;
  };

  storage.setItem = function(key, value) {
    dispatchStorageEvent(key, value);
    fakeLocalStorage[key] = String(value);
  };

  storage.removeItem = function(key) {
    dispatchStorageEvent(key, null);
    delete fakeLocalStorage[key];
  };

  storage.clear = function() {
    dispatchStorageEvent(null, null);
    fakeLocalStorage = {};
  };
};

// Example of how to use it
if (typeof window.localStorage === 'object') {
  // Safari will throw a fit if we try to use localStorage.setItem in private browsing mode. 
  try {
    localStorage.setItem('localStorageTest', 1);
    localStorage.removeItem('localStorageTest');
  } catch (e) {
    console.log("no localStorage");
    fakeLocalStorage();
  }
} else {
  // Use fake localStorage for any browser that does not support it.
  fakeLocalStorage();
}
