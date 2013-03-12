/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var CipherFox_prefs = (function() {
  'use strict';

  return {
    onLoad: function() {
      this.bundle = document.getElementById('cipherfox-prefs-bundle');
      this.baseFormat = document.getElementById('pref_base_format');
      this.certFormat = document.getElementById('pref_cert_format');
    }
  };
})();
