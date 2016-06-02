/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var CipherFox_prefs = (function() {
  'use strict';

  var Cc = Components.classes;
  var Ci = Components.interfaces;

  // exposed methods
  return {
    onLoad: function() {
      this.prompt = Cc['@mozilla.org/embedcomp/prompt-service;1']
        .getService(Ci.nsIPromptService);
      this.bundle = document.getElementById('cipherfox-prefs-bundle');
      this.baseFormat = document.getElementById('pref_base_format');
      this.certFormat = document.getElementById('pref_cert_format');
      this.headerFormat = document.getElementById('pref_header_format');
    }
  };
})();
