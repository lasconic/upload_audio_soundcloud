//=============================================================================
//
//  Soundcloud plugin for MuseScore
//  http://www.musescore.org/en/project/soundcloud
//
//  Copyright (C)2009 Nicolas Froment
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License version 2.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
//=============================================================================

//
//    This is ECMAScript code (ECMA-262 aka "Java Script")
//

/*
 * Copyright 2008 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Here's some JavaScript software for implementing OAuth.

   This isn't as useful as you might hope.  OAuth is based around
   allowing tools and websites to talk to each other.  However,
   JavaScript running in web browsers is hampered by security
   restrictions that prevent code running on one website from
   accessing data stored or served on another.

   Before you start hacking, make sure you understand the limitations
   posed by cross-domain XMLHttpRequest.

   On the bright side, some platforms use JavaScript as their
   language, but enable the programmer to access other web sites.
   Examples include Google Gadgets, and Microsoft Vista Sidebar.
   For those platforms, this library should come in handy.
*/

// The HMAC-SHA1 signature method calls b64_hmac_sha1, defined by
// http://pajhome.org.uk/crypt/md5/sha1.js

/* An OAuth message is represented as an object like this:
   {method: "GET", action: "http://server.com/path", parameters: ...}

   The parameters may be either a map {name: value, name2: value2}
   or an Array of name-value pairs [[name, value], [name2, value2]].
   The latter representation is more powerful: it supports parameters
   in a specific sequence, or several parameters with the same name;
   for example [["a", 1], ["b", 2], ["a", 3]].

   Parameter names and values are NOT percent-encoded in an object.
   They must be encoded before transmission and decoded after reception.
   For example, this message object:
   {method: "GET", action: "http://server/path", parameters: {p: "x y"}}
   ... can be transmitted as an HTTP request that begins:
   GET /path?p=x%20y HTTP/1.0
   (This isn't a valid OAuth request, since it lacks a signature etc.)
   Note that the object "x y" is transmitted as x%20y.  To encode
   parameters, you can call OAuth.addToURL, OAuth.formEncode or
   OAuth.getAuthorization.

   This message object model harmonizes with the browser object model for
   input elements of an form, whose value property isn't percent encoded.
   The browser encodes each value before transmitting it. For example,
   see consumer.setInputs in example/consumer.js.
 */

/* This script needs to know what time it is. By default, it uses the local
   clock (new Date), which is apt to be inaccurate in browsers. To do
   better, you can load this script from a URL whose query string contains
   an oauth_timestamp parameter, whose value is a current Unix timestamp.
   For example, when generating the enclosing document using PHP:

   <script src="oauth.js?oauth_timestamp=<?=time()?>" ...

   Another option is to call OAuth.correctTimestamp with a Unix timestamp.
 */

var OAuth; if (OAuth == null) OAuth = {};

OAuth.setProperties = function setProperties(into, from) {
    if (into != null && from != null) {
        for (var key in from) {
            into[key] = from[key];
        }
    }
    return into;
}

OAuth.setProperties(OAuth, // utility functions
{
    percentEncode: function percentEncode(s) {
        if (s == null) {
            return "";
        }
        if (s instanceof Array) {
            var e = "";
            for (var i = 0; i < s.length; ++s) {
                if (e != "") e += '&';
                e += OAuth.percentEncode(s[i]);
            }
            return e;
        }
        s = encodeURIComponent(s);
        // Now replace the values which encodeURIComponent doesn't do
        // encodeURIComponent ignores: - _ . ! ~ * ' ( )
        // OAuth dictates the only ones you can ignore are: - _ . ~
        // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
        s = s.replace(/\!/g, "%21");
        s = s.replace(/\*/g, "%2A");
        s = s.replace(/\'/g, "%27");
        s = s.replace(/\(/g, "%28");
        s = s.replace(/\)/g, "%29");
        return s;
    }
,
    decodePercent: function decodePercent(s) {
        if (s != null) {
            // Handle application/x-www-form-urlencoded, which is defined by
            // http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
            s = s.replace(/\+/g, " ");
        }
        return decodeURIComponent(s);
    }
,
    /** Convert the given parameters to an Array of name-value pairs. */
    getParameterList: function getParameterList(parameters) {
        if (parameters == null) {
            return [];
        }
        if (typeof parameters != "object") {
            return OAuth.decodeForm(parameters + "");
        }
        if (parameters instanceof Array) {
            return parameters;
        }
        var list = [];
        for (var p in parameters) {
            list.push([p, parameters[p]]);
        }
        return list;
    }
,
    /** Convert the given parameters to a map from name to value. */
    getParameterMap: function getParameterMap(parameters) {
        if (parameters == null) {
            return {};
        }
        if (typeof parameters != "object") {
            return OAuth.getParameterMap(OAuth.decodeForm(parameters + ""));
        }
        if (parameters instanceof Array) {
            var map = {};
            for (var p = 0; p < parameters.length; ++p) {
                var key = parameters[p][0];
                if (map[key] === undefined) { // first value wins
                    map[key] = parameters[p][1];
                }
            }
            return map;
        }
        return parameters;
    }
,
    getParameter: function getParameter(parameters, name) {
        if (parameters instanceof Array) {
            for (var p = 0; p < parameters.length; ++p) {
                if (parameters[p][0] == name) {
                    return parameters[p][1]; // first value wins
                }
            }
        } else {
            return OAuth.getParameterMap(parameters)[name];
        }
        return null;
    }
,
    formEncode: function formEncode(parameters) {
        var form = "";
        var list = OAuth.getParameterList(parameters);
        for (var p = 0; p < list.length; ++p) {
            var value = list[p][1];
            if (value == null) value = "";
            if (form != "") form += '&';
            form += OAuth.percentEncode(list[p][0])
              +'='+ OAuth.percentEncode(value);
        }
        return form;
    }
,
    decodeForm: function decodeForm(form) {
        var list = [];
        var nvps = form.split('&');
        for (var n = 0; n < nvps.length; ++n) {
            var nvp = nvps[n];
            if (nvp == "") {
                continue;
            }
            var equals = nvp.indexOf('=');
            var name;
            var value;
            if (equals < 0) {
                name = OAuth.decodePercent(nvp);
                value = null;
            } else {
                name = OAuth.decodePercent(nvp.substring(0, equals));
                value = OAuth.decodePercent(nvp.substring(equals + 1));
            }
            list.push([name, value]);
        }
        return list;
    }
,
    setParameter: function setParameter(message, name, value) {
        var parameters = message.parameters;
        if (parameters instanceof Array) {
            for (var p = 0; p < parameters.length; ++p) {
                if (parameters[p][0] == name) {
                    if (value === undefined) {
                        parameters.splice(p, 1);
                    } else {
                        parameters[p][1] = value;
                        value = undefined;
                    }
                }
            }
            if (value !== undefined) {
                parameters.push([name, value]);
            }
        } else {
            parameters = OAuth.getParameterMap(parameters);
            parameters[name] = value;
            message.parameters = parameters;
        }
    }
,
    setParameters: function setParameters(message, parameters) {
        var list = OAuth.getParameterList(parameters);
        for (var i = 0; i < list.length; ++i) {
            OAuth.setParameter(message, list[i][0], list[i][1]);
        }
    }
,
    /** Fill in parameters to help construct a request message.
        This function doesn't fill in every parameter.
        The accessor object should be like:
        {consumerKey:'foo', consumerSecret:'bar', accessorSecret:'nurn', token:'krelm', tokenSecret:'blah'}
        The accessorSecret property is optional.
     */
    completeRequest: function completeRequest(message, accessor) {
        if (message.method == null) {
            message.method = "GET";
        }
        var map = OAuth.getParameterMap(message.parameters);
        if (map.oauth_consumer_key == null) {
            OAuth.setParameter(message, "oauth_consumer_key", accessor.consumerKey || "");
        }
        if (map.oauth_token == null && accessor.token != null) {
            OAuth.setParameter(message, "oauth_token", accessor.token);
        }
        if (map.oauth_version == null) {
            OAuth.setParameter(message, "oauth_version", "1.0");
        }
        if (map.oauth_timestamp == null) {
            OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
        }
        if (map.oauth_nonce == null) {
            OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
        }
        OAuth.SignatureMethod.sign(message, accessor);
    }
,
    setTimestampAndNonce: function setTimestampAndNonce(message) {
        OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
        OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
    }
,
    addToURL: function addToURL(url, parameters) {
        newURL = url;
        if (parameters != null) {
            var toAdd = OAuth.formEncode(parameters);
            if (toAdd.length > 0) {
                var q = url.indexOf('?');
                if (q < 0) newURL += '?';
                else       newURL += '&';
                newURL += toAdd;
            }
        }
        return newURL;
    }
,
    /** Construct the value of the Authorization header for an HTTP request. */
    getAuthorizationHeader: function getAuthorizationHeader(realm, parameters) {
        var header = 'OAuth realm="' + OAuth.percentEncode(realm) + '"';
        var list = OAuth.getParameterList(parameters);
        for (var p = 0; p < list.length; ++p) {
            var parameter = list[p];
            var name = parameter[0];
            if (name.indexOf("oauth_") == 0) {
                header += ',' + OAuth.percentEncode(name) + '="' + OAuth.percentEncode(parameter[1]) + '"';
            }
        }
        return header;
    }
,
    /** Generate timestamps starting with the given value. */
    correctTimestamp: function correctTimestamp(timestamp) {
        OAuth.timeCorrectionMsec = (timestamp * 1000) - (new Date()).getTime();
    }
,
    /** The difference between the correct time and my clock. */
    timeCorrectionMsec: 0
,
    timestamp: function timestamp() {
        var t = (new Date()).getTime() + OAuth.timeCorrectionMsec;
        return Math.floor(t / 1000);
    }
,
    nonce: function nonce(length) {
        var chars = OAuth.nonce.CHARS;
        var result = "";
        for (var i = 0; i < length; ++i) {
            var rnum = Math.floor(Math.random() * chars.length);
            result += chars.substring(rnum, rnum+1);
        }
        return result;
    }
});

OAuth.nonce.CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";

/** Define a constructor function,
    without causing trouble to anyone who was using it as a namespace.
    That is, if parent[name] already existed and had properties,
    copy those properties into the new constructor.
 */
OAuth.declareClass = function declareClass(parent, name, newConstructor) {
    var previous = parent[name];
    parent[name] = newConstructor;
    if (newConstructor != null && previous != null) {
        for (var key in previous) {
            if (key != "prototype") {
                newConstructor[key] = previous[key];
            }
        }
    }
    return newConstructor;
}

/** An abstract algorithm for signing messages. */
OAuth.declareClass(OAuth, "SignatureMethod", function OAuthSignatureMethod(){});

OAuth.setProperties(OAuth.SignatureMethod.prototype, // instance members
{
    /** Add a signature to the message. */
    sign: function sign(message) {
        var baseString = OAuth.SignatureMethod.getBaseString(message);
        var signature = this.getSignature(baseString);
        OAuth.setParameter(message, "oauth_signature", signature);
        return signature; // just in case someone's interested
    }
,
    /** Set the key string for signing. */
    initialize: function initialize(name, accessor) {
        var consumerSecret;
        if (accessor.accessorSecret != null
            && name.length > 9
            && name.substring(name.length-9) == "-Accessor")
        {
            consumerSecret = accessor.accessorSecret;
        } else {
            consumerSecret = accessor.consumerSecret;
        }
        this.key = OAuth.percentEncode(consumerSecret)
             +"&"+ OAuth.percentEncode(accessor.tokenSecret);
    }
});

/* SignatureMethod expects an accessor object to be like this:
   {tokenSecret: "lakjsdflkj...", consumerSecret: "QOUEWRI..", accessorSecret: "xcmvzc..."}
   The accessorSecret property is optional.
 */
// Class members:
OAuth.setProperties(OAuth.SignatureMethod, // class members
{
    sign: function sign(message, accessor) {
        var name = OAuth.getParameterMap(message.parameters).oauth_signature_method;
        if (name == null || name == "") {
            name = "HMAC-SHA1";
            OAuth.setParameter(message, "oauth_signature_method", name);
        }
        OAuth.SignatureMethod.newMethod(name, accessor).sign(message);
    }
,
    /** Instantiate a SignatureMethod for the given method name. */
    newMethod: function newMethod(name, accessor) {
        var impl = OAuth.SignatureMethod.REGISTERED[name];
        if (impl != null) {
            var method = new impl();
            method.initialize(name, accessor);
            return method;
        }
        var err = new Error("signature_method_rejected");
        var acceptable = "";
        for (var r in OAuth.SignatureMethod.REGISTERED) {
            if (acceptable != "") acceptable += '&';
            acceptable += OAuth.percentEncode(r);
        }
        err.oauth_acceptable_signature_methods = acceptable;
        throw err;
    }
,
    /** A map from signature method name to constructor. */
    REGISTERED : {}
,
    /** Subsequently, the given constructor will be used for the named methods.
        The constructor will be called with no parameters.
        The resulting object should usually implement getSignature(baseString).
        You can easily define such a constructor by calling makeSubclass, below.
     */
    registerMethodClass: function registerMethodClass(names, classConstructor) {
        for (var n = 0; n < names.length; ++n) {
            OAuth.SignatureMethod.REGISTERED[names[n]] = classConstructor;
        }
    }
,
    /** Create a subclass of OAuth.SignatureMethod, with the given getSignature function. */
    makeSubclass: function makeSubclass(getSignatureFunction) {
        var superClass = OAuth.SignatureMethod;
        var subClass = function() {
            superClass.call(this);
        };
        subClass.prototype = new superClass();
        // Delete instance variables from prototype:
        // delete subclass.prototype... There aren't any.
        subClass.prototype.getSignature = getSignatureFunction;
        subClass.prototype.constructor = subClass;
        return subClass;
    }
,
    getBaseString: function getBaseString(message) {
        var URL = message.action;
        var q = URL.indexOf('?');
        var parameters;
        if (q < 0) {
            parameters = message.parameters;
        } else {
            // Combine the URL query string with the other parameters:
            parameters = OAuth.decodeForm(URL.substring(q + 1));
            var toAdd = OAuth.getParameterList(message.parameters);
            for (var a = 0; a < toAdd.length; ++a) {
                parameters.push(toAdd[a]);
            }
        }
        return OAuth.percentEncode(message.method.toUpperCase())
         +'&'+ OAuth.percentEncode(OAuth.SignatureMethod.normalizeUrl(URL))
         +'&'+ OAuth.percentEncode(OAuth.SignatureMethod.normalizeParameters(parameters));
    }
,
    normalizeUrl: function normalizeUrl(url) {
        var uri = OAuth.SignatureMethod.parseUri(url);
        var scheme = uri.protocol.toLowerCase();
        var authority = uri.authority.toLowerCase();
        var dropPort = (scheme == "http" && uri.port == 80)
                    || (scheme == "https" && uri.port == 443);
        if (dropPort) {
            // find the last : in the authority
            var index = authority.lastIndexOf(":");
            if (index >= 0) {
                authority = authority.substring(0, index);
            }
        }
        var path = uri.path;
        if (!path) {
            path = "/"; // conforms to RFC 2616 section 3.2.2
        }
        // we know that there is no query and no fragment here.
        return scheme + "://" + authority + path;
    }
,
    parseUri: function parseUri (str) {
        /* This function was adapted from parseUri 1.2.1
           http://stevenlevithan.com/demo/parseuri/js/assets/parseuri.js
         */
        var o = {key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
                 parser: {strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/ }};
        var m = o.parser.strict.exec(str);
        var uri = {};
        var i = 14;
        while (i--) uri[o.key[i]] = m[i] || "";
        return uri;
    }
,
    normalizeParameters: function normalizeParameters(parameters) {
        if (parameters == null) {
            return "";
        }
        var list = OAuth.getParameterList(parameters);
        var sortable = [];
        for (var p = 0; p < list.length; ++p) {
            var nvp = list[p];
            if (nvp[0] != "oauth_signature") {
                sortable.push([ OAuth.percentEncode(nvp[0])
                              + " " // because it comes before any character that can appear in a percentEncoded string.
                              + OAuth.percentEncode(nvp[1])
                              , nvp]);
            }
        }
        sortable.sort(function(a,b) {
                          if (a[0] < b[0]) return  -1;
                          if (a[0] > b[0]) return 1;
                          return 0;
                      });
        var sorted = [];
        for (var s = 0; s < sortable.length; ++s) {
            sorted.push(sortable[s][1]);
        }
        return OAuth.formEncode(sorted);
    }
});

OAuth.SignatureMethod.registerMethodClass(["PLAINTEXT", "PLAINTEXT-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return this.key;
        }
    ));

OAuth.SignatureMethod.registerMethodClass(["HMAC-SHA1", "HMAC-SHA1-Accessor"],
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            b64pad = '=';
            var signature = b64_hmac_sha1(this.key, baseString);
            return signature;
        }
    ));



/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s){return binb2hex(core_sha1(str2binb(s),s.length * chrsz));}
function b64_sha1(s){return binb2b64(core_sha1(str2binb(s),s.length * chrsz));}
function str_sha1(s){return binb2str(core_sha1(str2binb(s),s.length * chrsz));}
function hex_hmac_sha1(key, data){ return binb2hex(core_hmac_sha1(key, data));}
function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}
function str_hmac_sha1(key, data){ return binb2str(core_hmac_sha1(key, data));}

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
  return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}




//---------------------------------------------------------
//    init
//    this function will be called on startup of
//    mscore
//---------------------------------------------------------

function init()
      {
      // print("test script init");
      }

function testOAuth() {
    testEncode();
    testGetParameters();
    testGetBaseString();
    testGetSignature();
}

var ENCODING // From http://wiki.oauth.net/TestCases
  = [ ["abcABC123", "abcABC123"]
    , ["-._~"     , "-._~"]
    , ["%"        , "%25"]
    , ["+"        , "%2B"]
    , ["&=*"      , "%26%3D%2A"]
    , ["!'()"     , "%21%27%28%29"]
    , ["\n"       , "%0A"]
    , [" "        , "%20"]
    ];

function testEncode() {
    for (var i = 0; i < ENCODING.length; ++i) {
        var input    = ENCODING[i][0];
        var expected = ENCODING[i][1];
        var actual = OAuth.percentEncode(input);
        if (expected != actual) {
            print("OAuth.percentEncode(" + input + ") = " + actual);
        }
    }
}

function testGetParameters() {
    var list = OAuth.getParameterList(null);
    if (list == null || !(list instanceof Array) || list.length != 0) {
        print("getParameterList(null) = " + list);
    }
    list = OAuth.getParameterList('');
    if (list == null || !(list instanceof Array) || list.length != 0) {
        print("getParameterList('') = " + list);
    }
    var map = OAuth.getParameterMap(null);
    if (map == null || (map instanceof Array) || typeof map != "object") {
        print("getParameterMap(null) = " + map);
    }
    var actual = OAuth.getParameter({x: 'a', y: 'b'}, 'x');
    if (actual != 'a') {
        print("getParameter({}, 'x') = " + actual);
    }
    actual = OAuth.getParameter([['x', 'a'], ['y', 'b'], ['x', 'c']], 'x');
    if (actual != 'a') {
        print("getParameter([], 'x') = " + actual);
    }
    var expected = 'OAuth realm="R",oauth_token="T",oauth_w%40%21rd="%23%40%2A%21"';
    actual = OAuth.getAuthorizationHeader('R', [['a', 'b'], ['oauth_token', 'T'], ['oauth_w@!rd', '#@*!']]);
    if (actual == null || actual != expected) {
        print("getAuthorizationHeader\n" + expected + " != \n" + actual);
    }
    actual = OAuth.getAuthorizationHeader('R', {a: 'b', oauth_token: 'T', 'oauth_w@!rd': '#@*!'});
    if (actual == null || actual != expected) {
        print("getAuthorizationHeader\n" + expected + " != \n" + actual);
    }
    var message = {action: 'http://localhost', parameters: {}};
    OAuth.completeRequest(message, {consumerKey: 'CK', token: 'T'});
    assertMemberEquals(message, 'method', "GET");
    map = message.parameters;
    assertMemberEquals(map, 'oauth_consumer_key', 'CK');
    assertMemberEquals(map, 'oauth_token', 'T');
    assertMemberEquals(map, 'oauth_version', '1.0');
    assertMemberNotNull(map, 'oauth_timestamp');
    assertMemberNotNull(map, 'oauth_nonce');
}

function assertMemberEquals(map, name, expected) {
    var actual = map[name];
    if (actual != expected) {
        print(name + '=' + actual + ' (not ' + expected + ')');
    }
}

function assertMemberNotNull(map, name) {
    var actual = map[name];
    if (!actual) {
        print(name + '=' + actual);
    }
}

var OAUTH_A_BASE_STRING = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&"
    + "file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";

var BASES = //
    // label, HTTP method, action, parameters, expected
    { "simple"         : ["GET", "http://example.com/", {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "no path"        : ["GET", "http://example.com" , {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "sorting"        : ["GET", "http://example.com/", [["n", "AB"], ["n", "{}"]], "GET&http%3A%2F%2Fexample.com%2F&n%3D%257B%257D%26n%3DAB" ]
    , "OAuth A request": ["POST", "https://photos.example.net/request_token",
            { oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03"
            , oauth_timestamp: "1191242090", oauth_nonce: "hsu94j3884jdopsl"
            , oauth_signature_method: "PLAINTEXT", oauth_signature: "ignored"
            }
            , "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&"
                 + "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0" ]
    , "OAuth A access" : ["GET", "http://photos.example.net/photos",
            { file: "vacation.jpg", size: "original"
            , oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03", oauth_token: "nnch734d00sl2jdk"
            , oauth_timestamp: "1191242096", oauth_nonce: "kllo9940pd9333jh"
            , oauth_signature: "ignored", oauth_signature_method: "HMAC-SHA1"
            }
            , OAUTH_A_BASE_STRING ]
    };

function testGetBaseString() {
    for (var label in BASES) {
        try {
            var base = BASES[label];
            var b = 0;
            var method = base[b++];
            var action = base[b++];
            var parameters = base[b++];
            var expected = base[b++];
            var actual = OAuth.SignatureMethod.getBaseString({method: method, action: action, parameters: parameters});
            if (expected != actual) {
                print(label + "\n" + actual + " (actual)\n" + expected + " (expected)");
            }
        } catch(e) {
            print(e);
        }
    }
    // print("tested OAuth.SignatureMethod.getBaseString");
}

var SIGNATURES =
// label, method, consumer secret, token secret, base string, expected
{ "HMAC-SHA1.a"    : [ "HMAC-SHA1", "cs", null, "bs", "egQqG5AJep5sJ7anhXju1unge2I=" ]
, "HMAC-SHA1.b"    : [ "HMAC-SHA1", "cs", "ts", "bs", "VZVjXceV7JgPq/dOTnNmEfO0Fv8=" ]
, "OAuth A access" : [ "HMAC-SHA1", "kd94hf93k423kf44",
                       "pfkkdhi9sl3r4s00", OAUTH_A_BASE_STRING,
                       "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" ]
, "PLAINTEXT"      : [ "PLAINTEXT", "cs", "ts", "bs", "cs&ts" ]
, "OAuth A request": [ "PLAINTEXT", "kd94hf93k423kf44", null, null, "kd94hf93k423kf44&" ]
};

function testGetSignature() {
    for (label in SIGNATURES) {
        try {
            var signature = SIGNATURES[label];
            var s = 0;
            var methodName = signature[s++];
            var consumerSecret = signature[s++];
            var tokenSecret = signature[s++];
            var baseString = signature[s++];
            var expected = signature[s++];
            var signer = OAuth.SignatureMethod.newMethod(methodName,
                         {consumerSecret: consumerSecret, tokenSecret: tokenSecret});
            var actual = signer.getSignature(baseString);
            if (expected != actual) {
                print(label + "\n" + actual + " (actual)\n" + expected + " (expected)");
            }
        } catch(e) {
            print(label + ": " + e);
        }
    }
    // print("tested OAuth.SignatureMethod.getSignature");
}


var consumer =
{ consumerKey   : "gJLBoOosc0jOK2vUh7TZGw"
, consumerSecret: "pfyQIK56joOnLlwEkn50e6SbBssaot7yzYXmGM4polY"
, serviceProvider:
  { signatureMethod     : "HMAC-SHA1"
  , requestTokenURL     : "http://api.soundcloud.com/oauth/request_token"
  , userAuthorizationURL: "http://soundcloud.com/oauth/authorize"
  , accessTokenURL      : "http://api.soundcloud.com/oauth/access_token"
  }
};

var hostApi = "api.soundcloud.com";


//Sandbox
/*var consumer =
{ consumerKey   : "WcZawAeTKP2RVSDG7az61Q"
, consumerSecret: "TFsE7tjkktunQ3zk0d9Ox7glWliV53NMHg1VFZZDU"
, serviceProvider:
  { signatureMethod     : "HMAC-SHA1"
  , requestTokenURL     : "http://api.sandbox-soundcloud.com/oauth/request_token"
  , userAuthorizationURL: "http://sandbox-soundcloud.com/oauth/authorize"
  , accessTokenURL      : "http://api.sandbox-soundcloud.com/oauth/access_token"
  }
};
var hostApi = "api.sandbox-soundcloud.com";*/

QByteArray.prototype.toString = function(codec)
{
   ts = new QTextStream( this, QIODevice.ReadOnly );
   if(codec && codec!="")
      ts.setCodec(codec);
   return ts.readAll();
}

function utf8_encode ( argString ) {
    // Encodes an ISO-8859-1 string to UTF-8  
    // 
    // version: 909.322
    // discuss at: http://phpjs.org/functions/utf8_encode
    // +   original by: Webtoolkit.info (http://www.webtoolkit.info/)
    // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
    // +   improved by: sowberry
    // +    tweaked by: Jack
    // +   bugfixed by: Onno Marsman
    // +   improved by: Yves Sucaet
    // +   bugfixed by: Onno Marsman
    // +   bugfixed by: Ulrich
    // *     example 1: utf8_encode('Kevin van Zonneveld');
    // *     returns 1: 'Kevin van Zonneveld'
    var string = (argString+''); // .replace(/\r\n/g, "\n").replace(/\r/g, "\n");
 
    var utftext = "";
    var start, end;
    var stringl = 0;
 
    start = end = 0;
    stringl = string.length;
    for (var n = 0; n < stringl; n++) {
        var c1 = string.charCodeAt(n);
        var enc = null;
 
        if (c1 < 128) {
            end++;
        } else if (c1 > 127 && c1 < 2048) {
            enc = String.fromCharCode((c1 >> 6) | 192) + String.fromCharCode((c1 & 63) | 128);
        } else {
            enc = String.fromCharCode((c1 >> 12) | 224) + String.fromCharCode(((c1 >> 6) & 63) | 128) + String.fromCharCode((c1 & 63) | 128);
        }
        if (enc !== null) {
            if (end > start) {
                utftext += string.substring(start, end);
            }
            utftext += enc;
            start = end = n+1;
        }
    }
 
    if (end > start) {
        utftext += string.substring(start, string.length);
    }
 
    return utftext;
}

//---------------------------------------------------------
//    run
//    this function will be called when activating the
//    plugin menu entry
//
//    global Variables:
//    pluginPath - contains the plugin path; file separator
//                 is "/"
//---------------------------------------------------------

var answerBuffer;
var requestId;
var dirSettings = QDir.homePath() + "/.musescore/plugins/soundcloud";
var fileSettings = "settings.txt";

function run()
  {
    if(loadSettings()){
      testGet();
    }else{
      requestToken();
    }
  }
  
function requestToken(){

    var accessor = { consumerSecret: consumer.consumerSecret
                   , tokenSecret   : ""};
    var message = { action: consumer.serviceProvider.requestTokenURL
                  , method: "POST"
                  , parameters: []
                  };

    message.parameters.push(["oauth_consumer_key" , consumer.consumerKey]);
    message.parameters.push(["oauth_signature_method" , consumer.serviceProvider.signatureMethod]);
    message.parameters.push(["oauth_timestamp" , ""]);
    message.parameters.push(["oauth_nonce" , ""]);
    message.parameters.push(["oauth_signature" , ""]);
    message.parameters.push(["oauth_callback" , "oob"]);
    
    OAuth.setTimestampAndNonce(message);
    OAuth.SignatureMethod.sign(message, accessor);

    // content
    var content = new QByteArray();
    var body = OAuth.formEncode(message.parameters);
    content.append(body);
    
    var contentLength = content.length();
    var buffer = new QBuffer(content);
    
    // header
    var header = new QHttpRequestHeader("POST", "/oauth/request_token");
    header.setValue("Host", hostApi);    
    header.setContentType("application/x-www-form-urlencoded"); // important
    header.setContentLength(contentLength);
    
    // request
    answerBuffer = new QBuffer();
    answerBuffer.open(QIODevice.OpenMode(QIODevice.ReadWrite));
    var http = new QHttp();
    http.setHost(hostApi);
    http.requestFinished.connect(answerBuffer, processAnswerRequestToken);
    requestId = http.request(header, buffer, answerBuffer);
}  
  
function processAnswerRequestToken(id ,error){
  if (id == requestId){
    answerBuffer.seek(0);
    var c = answerBuffer.readAll();
    var stringResult = c.toString();
    answerBuffer.close();
    if(!error){
        var results = OAuth.decodeForm(stringResult);
        consumer.token = OAuth.getParameter(results, "oauth_token");
        consumer.tokenSecret = OAuth.getParameter(results, "oauth_token_secret");
        
        //open browser at http://soundcloud.com/oauth/authorize?oauth_token=
        var url = consumer.serviceProvider.userAuthorizationURL + "?" + "oauth_token=" + consumer.token;
    
        // QDesktopServices.openUrl(url);    // Does not work ...
        
        var loader = new QUiLoader(null);
        var file   = new QFile(pluginPath + "/authorize_dialog.ui");
        file.open(QIODevice.OpenMode(QIODevice.ReadOnly, QIODevice.Text));
        form = loader.load(file, null);
        form.label.text = "1 - Please <a href='"+url+"'>click here</a> to authorize MuseScore. <br/>2 - Enter the provided code and press OK.";
        form.buttonBox.accepted.connect(acceptAuthorize);
        form.show();  
      
    }else{
         //message error
        QMessageBox.critical(0, "Error", "Cannot get request token [" + stringResult+ "]" );
    }
  }
}

function acceptAuthorize(){

        var code = form.hl.lineEdit.text;
        if(code && code.length > 0){
          getAccessToken(code);
        }else{
          //message error
          QMessageBox.critical(0, "Error", "You must provide the authorization code.");
        }
}

function getAccessToken(code){
    var accessor = { consumerSecret: consumer.consumerSecret 
                   , tokenSecret   : consumer.tokenSecret};
    var message = { action: consumer.serviceProvider.accessTokenURL
                  , method: "POST"
                  , parameters: []
                  };

    message.parameters.push(["oauth_consumer_key" , consumer.consumerKey]);
    message.parameters.push(["oauth_token" , consumer.token]);
    message.parameters.push(["oauth_signature_method" , consumer.serviceProvider.signatureMethod]);
    message.parameters.push(["oauth_timestamp" , ""]);
    message.parameters.push(["oauth_nonce" , ""]);
    message.parameters.push(["oauth_signature" , ""]);
    message.parameters.push(["oauth_verifier" , code]);
    
    OAuth.setTimestampAndNonce(message);
    OAuth.SignatureMethod.sign(message, accessor);

    // content
    var content = new QByteArray();
    var body = OAuth.formEncode(message.parameters);
    content.append(body);

    var contentLength = content.length();
    var buffer = new QBuffer(content);
    
    // header
    var header = new QHttpRequestHeader("POST", "/oauth/access_token");
    header.setValue("Host", hostApi);    
    header.setContentType("application/x-www-form-urlencoded"); // important
    header.setContentLength(contentLength);
    
    // request
    answerBuffer = new QBuffer();
    answerBuffer.open(QIODevice.OpenMode(QIODevice.ReadWrite));
    var http = new QHttp();
    http.setHost(hostApi);
    http.requestFinished.connect(answerBuffer, processAnswerAccessToken);
    requestId = http.request(header, buffer, answerBuffer);
}

function processAnswerAccessToken(id ,error){
  if (id == requestId){
    answerBuffer.seek(0);
    var c = answerBuffer.readAll();
    var stringResult = c.toString();
    answerBuffer.close();
    if(!error){
        var results = OAuth.decodeForm(stringResult);
        consumer.accessToken = OAuth.getParameter(results, "oauth_token");
        consumer.accessTokenSecret = OAuth.getParameter(results, "oauth_token_secret");
        saveSettings();
        formBeforeUpload();
    }else{
        //message error
        QMessageBox.critical(0, "Error", "Cannot get access token [" + stringResult+ "]");
    }      
  }
}

function formBeforeUpload(){
      var loader = new QUiLoader(null);
      var file   = new QFile(pluginPath + "/soundcloud_dialog.ui");
      file.open(QIODevice.OpenMode(QIODevice.ReadOnly, QIODevice.Text));
      form = loader.load(file, null);
      form.verticalLayoutWidget.title.text = curScore.name;
      form.verticalLayoutWidget.tags.text = "musescore";
      form.buttonBox.accepted.connect(saveAndUpload);
      form.show();  
}




/****************************
*   Save & upload
*****************************/
function saveAndUpload(){
  var path = QDir.tempPath() + "/" + curScore.name + ".ogg";
  if(curScore.save(path, 'ogg')){

      var licenses = ["all-rights-reserved", "no-rights-reserved", "cc-by","cc-by-nc","cc-by-nd","cc-by-sa","cc-by-nc-nd","cc-by-nc-sa"];
      var description = form.verticalLayoutWidget.description.plainText;
      var title = form.verticalLayoutWidget.title.text;
      var genre = form.verticalLayoutWidget.genre.text;
      var tags = form.verticalLayoutWidget.tags.text;
      //var bpm = form.verticalLayoutWidget.BPM.text;
      var publicAccess = form.verticalLayoutWidget.rbPublic.checked;
      //var key = form.verticalLayoutWidget.key.currentIndex;
      var license = licenses[form.verticalLayoutWidget.license.currentIndex];
      var sharing = publicAccess ? "public" : "private";
      
      var accessor = { consumerSecret: consumer.consumerSecret 
                   , tokenSecret   : consumer.accessTokenSecret
                   };
                   
      var message = { action: "http://"+hostApi+"/tracks"
                  , method: "POST"
                  , parameters: []
                  };

      message.parameters.push(["oauth_consumer_key" , consumer.consumerKey]);
      message.parameters.push(["oauth_token" , consumer.accessToken]);
      message.parameters.push(["oauth_signature_method" , consumer.serviceProvider.signatureMethod]);
    
      OAuth.completeRequest(message, accessor);

      var boundary = Math.round(Math.random()*1000000000000);
      
      // header
      var header = new QHttpRequestHeader("POST", "/tracks");
      header.setValue("Host", hostApi);    
      header.setContentType("multipart/form-data; boundary=---------------------------"+boundary); // important
      
      var realm = OAuth.getAuthorizationHeader("",message.parameters);
      header.setValue("Authorization", realm);

      // content      
      var content = new QByteArray();
      var oggFile = new QFile(path);
      oggFile.open(QIODevice.OpenMode(QIODevice.ReadOnly));    
      content.append("-----------------------------"+boundary+"\r\n");
      content.append("Content-Disposition: form-data; name=\"track[asset_data]\"; filename=\""+curScore.name+".ogg\"\r\n");
      content.append("Content-Type: application/octet-stream\r\n");
      content.append("Content-Transfer-Encoding: binary\r\n\r\n"); 
      content.append(oggFile.readAll());
      oggFile.close();
      oggFile.remove();
      content.append("\r\n");
      content.append("-----------------------------"+boundary+"\r\n");
      content.append("Content-Disposition: form-data; name=\"track[title]\"\r\n\r\n");
      content.append(utf8_encode(title));
      content.append("\r\n");
      
      if(description && description!=""){
        content.append("-----------------------------"+boundary+"\r\n");
        content.append("Content-Disposition: form-data; name=\"track[description]\"\r\n\r\n");
        //content.append("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        content.append(utf8_encode(description));
        content.append("\r\n");
      }
      
      if(genre && genre!=""){
        content.append("-----------------------------"+boundary+"\r\n");
        content.append("Content-Disposition: form-data; name=\"track[genre]\"\r\n\r\n");
        content.append(utf8_encode(genre));
        content.append("\r\n");
      }
      
      if(tags && tags!=""){
        content.append("-----------------------------"+boundary+"\r\n");
        content.append("Content-Disposition: form-data; name=\"track[tag_list]\"\r\n\r\n");
        content.append(utf8_encode(tags));
        content.append("\r\n");
      }
      
      if(license && license!=""){
        content.append("-----------------------------"+boundary+"\r\n");
        content.append("Content-Disposition: form-data; name=\"track[license]\"\r\n\r\n");
        content.append(license);
        content.append("\r\n");
      }
      
      content.append("-----------------------------"+boundary+"\r\n");
      content.append("Content-Disposition: form-data; name=\"track[sharing]\"\r\n\r\n");
      content.append(sharing);
      content.append("\r\n");
      
      content.append("-----------------------------"+boundary+"--\r\n");
      
      var contentLength = content.length();
      var buffer = new QBuffer(content);
    
      header.setContentLength(contentLength);
      
      // request
      answerBuffer = new QBuffer();
      answerBuffer.open(QIODevice.OpenMode(QIODevice.ReadWrite));
      var http = new QHttp();
      http.setHost(hostApi);
      http.dataSendProgress.connect(answerBuffer, processDataSendProgress);
      http.requestFinished.connect(answerBuffer, processAnswerUpload);
      
      var loader = new QUiLoader(null);
      var file   = new QFile(pluginPath + "/soundcloud_progress.ui");
      file.open(QIODevice.OpenMode(QIODevice.ReadOnly, QIODevice.Text));
      form = loader.load(file, null);
      form.setWindowFlags(Qt.CustomizeWindowHint);
      form.progressBar.value = 0;
      requestId = http.request(header, buffer, answerBuffer);
      form.show();
  }
}

function processDataSendProgress(done, total){
  form.progressBar.value = (100*done)/total;
}

function processAnswerUpload(id ,error){
  if (id == requestId){
    if(!error){
      form.close(); 
      answerBuffer.seek(0);
      var c = answerBuffer.readAll();
      var stringResult = c.toString();
      //answerBuffer.close();
      print(stringResult);
      answerBuffer.seek(0);
      var reader = new QXmlStreamReader;
      reader.setDevice(answerBuffer);
      var permalink = "";
      while (!reader.atEnd())
      {
        if (reader.isStartElement()) 
        {
          if (reader.name() == "permalink-url") 
          {
              permalink = reader.readElementText();
              break;

          }
        }
        reader.readNext(); 
      }
      answerBuffer.close();
      if (permalink && permalink!=""){
          print(permalink);
          QMessageBox.about(0, "Success", "Your track is available on <a href='"+permalink+"'>SoundCloud</a>.");
      }else{
         QMessageBox.critical(0, "Error2", "An error occurred while uploading to SoundCloud.");
      }
    }else{
        form.close(); 
        QMessageBox.critical(0, "Error", "An error occurred while uploading to SoundCloud.");
    } 
    
  }
}

/****************************
*   Test function
*****************************/
function testGet(){
      var accessor = { consumerSecret: consumer.consumerSecret 
                   , tokenSecret   : consumer.accessTokenSecret
                   };
                   
      var message = { action: "http://"+hostApi+"/oauth/test_request"
                  , method: "GET"
                  , parameters: []
                  };

      message.parameters.push(["oauth_consumer_key" , consumer.consumerKey]);
      message.parameters.push(["oauth_token" , consumer.accessToken]);
      message.parameters.push(["oauth_signature_method" , consumer.serviceProvider.signatureMethod]);
    
      OAuth.completeRequest(message, accessor);
      
      var http = new QHttp();
      http.setHost(hostApi);
      http.requestFinished.connect(answerBuffer, processTestGet);
      var url = OAuth.addToURL("http://"+hostApi+"/oauth/test_request", message.parameters); 
      
      requestId = http.get(url);
      
}

function processTestGet(id ,error){
  if (id == requestId){
    if(!error){
      formBeforeUpload();
    }else{
      requestToken();
    }
  }
}
/**********************************************************
 *  Serialize an array. Array can be read back with eval
 *********************************************************/
function serialize(input){
  var objStr = '';
  var i = 0;
  for (var p in input)
  {
    if (i == 0)
      objStr+="{ ";
    else{
      objStr+=" , ";
    }
    if(input[p]!= "[object Object]")
      objStr += p + ": \"" + input[p] + "\"";
    else
      objStr +=  p + ": " + serialize(input[p]);     
    i++;
  }
   objStr+=" }";
  return objStr;
} 

/**********************************************************
 *  Save the settings
 *********************************************************/
function saveSettings(){
    var settings = serialize(consumer);
    var dir = new QDir;
    if(dir.mkpath(dirSettings)){
      var settingsFile = new QFile(dirSettings+ "/"+ fileSettings);
      if(settingsFile.open(QIODevice.OpenMode(QIODevice.WriteOnly))){
        var ba = new QByteArray(settings);
        settingsFile.write(ba); 
        settingsFile.flush();
        settingsFile.close();
      }else{
        QMessageBox.critical(0, "Error", "Cannot write settings.");
      }
    }else{
      QMessageBox.critical(0, "Error", "Cannot create settings directory.");
    }
}

/**********************************************************
 *  Load the settings
 *********************************************************/
function loadSettings(){
    var settingsFile = new QFile(dirSettings+ "/"+ fileSettings);
    if (settingsFile.open(QIODevice.OpenMode(QIODevice.ReadOnly))){
      var settings = settingsFile.readAll().toString(); 
      settingsFile.flush();
      settingsFile.close();
      if(settings && settings != ""){
          consumer = eval('(' + settings + ')');
          return true;
      }
    }
    return false;
}


//---------------------------------------------------------
//    menu:  defines were the function will be placed
//           in the menu structure
//---------------------------------------------------------

var mscorePlugin = {
      menu: 'Plugins.Upload to SoundCloud',
      init: init,
      run:  run
      };

mscorePlugin;

