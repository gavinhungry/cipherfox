/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

CipherFox_prefs = (() => {
  'use strict';

  const Cc = Components.classes;
  const Ci = Components.interfaces;

  // exposed methods
  return {
    onLoad: () => {
      CipherFox_prefs.prompt = Cc['@mozilla.org/embedcomp/prompt-service;1']
        .getService(Ci.nsIPromptService);
      CipherFox_prefs.bundle = document.getElementById('cipherfox-prefs-bundle');
      CipherFox_prefs.baseFormat = document.getElementById('pref_base_format');
      CipherFox_prefs.certFormat = document.getElementById('pref_cert_format');
      CipherFox_prefs.headerFormat = document.getElementById('pref_header_format');
    }
  };
})();
