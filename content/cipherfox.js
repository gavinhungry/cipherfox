/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var CipherFox = (function() {
  'use strict';

  const Cc = Components.classes, Ci = Components.interfaces;

  var certDb  = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB);
  var certDlg = Cc['@mozilla.org/nsCertificateDialogs;1'].getService(Ci.nsICertificateDialogs);
  var pipnss  = Cc['@mozilla.org/intl/stringbundle;1'].getService(Ci.nsIStringBundleService)
                .createBundle('chrome://pipnss/locale/pipnss.properties');

  var prefService = Cc['@mozilla.org/preferences-service;1'].getService(Ci.nsIPrefBranch2);
  var prefs = {};
  var rc4Enabled;

  // ciphers from ciphersuites
  var ciphers = ['_AES_', '_RC4_', '_3DES_', '_DES_', '_CAMELLIA_', '_RC2_',
    '_DES40_', '_FORTEZZA_', '_IDEA_', '_SEED_', '_GOST', '_NULL_'];
  var ciphersRe = new RegExp(ciphers.join('|'));

  // default SSL3 RC4 preferences
  var rc4 = ['ecdh_ecdsa_rc4_128_sha', 'ecdh_rsa_rc4_128_sha',
    'ecdhe_ecdsa_rc4_128_sha', 'ecdhe_rsa_rc4_128_sha', 'rsa_1024_rc4_56_sha',
    'rsa_rc4_128_md5', 'rsa_rc4_128_sha', 'rsa_rc4_40_md5'];

  // XUL DOM elements
  var cfToggle, cfPanel, cfButton, cfCerts, cfBCerts, cfPSep;

  var hideIdentityPopup = function() {
    gIdentityHandler.hideIdentityPopup && gIdentityHandler.hideIdentityPopup();
  };

  // show dialog for cert in database
  var viewCertByDBKey = function(e) {
    hideIdentityPopup();

    var dbkey = e.target.getAttribute('dbkey');
    var cert = certDb.findCertByDBKey(dbkey, null);
    certDlg.viewCert(window, cert);
  };

  // update RC4 preferences
  var setRC4 = function() {
    for (var i = 0, len = rc4.length; i < len; i++) {
      var pref = 'security.ssl3.' + rc4[i];

      if (rc4Enabled) {
        try { prefService.clearUserPref(pref); }
        catch(e) {}
      } else if (getBoolPref(pref) !== undefined) {
        prefService.setBoolPref(pref, false);
      }
    }
  };

  var toggleRC4 = function() {
    rc4Enabled = !rc4Enabled;
    cfToggle.setAttribute('checked', rc4Enabled);
    setRC4();
  };

  // get existing preferences
  var loadPrefs = function() {
    prefs.base_format  = prefService.getCharPref('extensions.cipherfox.base_format');
    prefs.cert_format  = prefService.getCharPref('extensions.cipherfox.cert_format');
    prefs.disable_rc4  = prefService.getBoolPref('extensions.cipherfox.disable_rc4');
    prefs.show_builtin = prefService.getBoolPref('extensions.cipherfox.show_builtin');
    prefs.show_partial = prefService.getBoolPref('extensions.cipherfox.show_partial');
    prefs.show_panel   = prefService.getBoolPref('extensions.cipherfox.show_panel');
    prefs.show_button  = prefService.getBoolPref('extensions.cipherfox.show_button');

    // set RC4 status and menuitem
    rc4Enabled = !prefs.disable_rc4;
    cfToggle.setAttribute('hidden', rc4Enabled);
    cfToggle.setAttribute('checked', rc4Enabled);
  };

  // get all certs and update
  var populateCertChain = function(status) {

    cfCerts.hidePopup();
    cfBCerts.hidePopup();

    // remove old certs
    while(cfCerts.hasChildNodes()) {
      cfCerts.removeChild(cfCerts.firstChild);
    }

    while(cfBCerts.hasChildNodes() && cfBCerts.firstChild !== cfPSep) {
      cfBCerts.removeChild(cfBCerts.firstChild);
    }

    var serverCert = status.serverCert;
    if (serverCert instanceof Ci.nsIX509Cert) {
      var certChain = serverCert.getChain().enumerate();

      while (certChain.hasMoreElements()) {
        var next = certChain.getNext();
        var cert = next.QueryInterface(Ci.nsIX509Cert || Ci.nsIX509Cert2);

        var certItem = document.createElement('menuitem');

        if (cert.tokenName === 'Builtin Object Token' &&
            cert.certType === Ci.nsIX509Cert.CA_CERT) {
          if (!prefs.show_builtin) { continue; }
          certItem.setAttribute('builtin', true);
        }

        var label = formatLabel(cert);
        var dbkey = cert.dbKey.replace(/[\n\r\t]/g, '');

        // selecting a cert brings up details
        certItem.setAttribute('label', label);
        certItem.setAttribute('dbkey', dbkey);

        // add attributes for styling
        certItem.setAttribute('cert', true);
        if (!cfCerts.hasChildNodes()) {
          certItem.setAttribute('first', true);
        }

        certItem.addEventListener('command', viewCertByDBKey, false);

        var certItemB = certItem.cloneNode(false);
        certItemB.addEventListener('command', viewCertByDBKey, false);

        cfCerts.insertBefore(certItem, cfCerts.firstChild);
        cfBCerts.insertBefore(certItemB, cfPSep);
      }
    }
  };

  var formatLabel = function(obj) {
    var cert, label;

    if (obj instanceof Ci.nsISSLStatus) {
      cert = obj.serverCert;
      label = prefs.base_format;

      var cipherName = obj.cipherName
      var suiteMatch = ciphersRe.exec(cipherName);

      var cipherSuite = '';

      // in Firefox 25+, cipherName contains a full cipher suite
      if (suiteMatch) {
        cipherSuite = cipherName; // full cipher suite
        cipherName = suiteMatch[0].replace(/_/g, ''); // short cipher name
      } else {
        cipherName = cipherName.split('-')[0];
      }

      label = label
        .replace(/\$CIPHERALG/g, cipherName)
        .replace(/\$CIPHERSIZE/g, obj.secretKeyLength)
        .replace(/\$CIPHERSUITE/g, cipherSuite);

    } else if (obj instanceof Ci.nsIX509Cert) {
      cert = obj;
      label = prefs.cert_format;
    } else { return null; }

    var certDmp = Cc['@mozilla.org/security/nsASN1Tree;1'].createInstance(Ci.nsIASN1Tree);
    certDmp.loadASN1Structure(cert.ASN1Structure);

    var certOrg = cert.organization ? cert.organization : cert.commonName;
    var certCn  = cert.commonName   ? cert.commonName   : cert.organization;

    var certAlg;
    switch (certDmp.getDisplayData(11)) {
      case pipnss.GetStringFromName('CertDumpRSAEncr'):
        certAlg = 'RSA';
        break;
    }

    if (!certAlg) {
      switch (certDmp.getDisplayData(12)) {
        case pipnss.GetStringFromName('CertDumpECPublicKey'):
          certAlg = 'ECC';
          break;
        case pipnss.GetStringFromName('CertDumpAnsiX9DsaSignature'):
        case pipnss.GetStringFromName('CertDumpAnsiX9DsaSignatureWithSha1'):
          certAlg = 'DSA';
          break;
      }
    }

    var certSize, key, template;
    try {
      switch(certAlg) {
        case 'RSA':
          key = certDmp.getDisplayData(12).split('\n')[0];
          template = pipnss.GetStringFromName('CertDumpRSATemplate');
          break;

        case 'ECC':
          key = certDmp.getDisplayData(14).split('\n')[0];
          template = pipnss.GetStringFromName('CertDumpECTemplate');
          break;

        case 'DSA':
          key = certDmp.getDisplayData(14);
          key = key.replace(key.split('\n')[0], '').replace(/\n|(\s$)/g, '').split(/\s/);
          if (key[0] === '02' && key[1] === '81') { key.splice(0,3); }
          if (key[0] === '00') { key.splice(0,1); }
          certSize = (8 * key.length);
          break;
      }

      if (!certSize && template) {
        var discards = template.split('\n')[0].split('%S');
        discards.forEach(function(str) {
          key = key.replace(str, '');
        });

        certSize = key;
      }
    } catch(e) {}

    // look for hash type
    var certHash;
    switch (certDmp.getDisplayData(certDmp.rowCount-2)) {
      case pipnss.GetStringFromName('CertDumpMD2WithRSA'):    certHash = 'MD2';    break;
      case pipnss.GetStringFromName('CertDumpMD5WithRSA'):    certHash = 'MD5';    break;
      case pipnss.GetStringFromName('CertDumpSHA1WithRSA'):   certHash = 'SHA1';   break;
      case pipnss.GetStringFromName('CertDumpSHA256WithRSA'): certHash = 'SHA256'; break;
      case pipnss.GetStringFromName('CertDumpSHA384WithRSA'): certHash = 'SHA384'; break;
      case pipnss.GetStringFromName('CertDumpSHA512WithRSA'): certHash = 'SHA512';
    }

    var certFrom = cert.validity.notBeforeLocalDay;
    var certExp = cert.validity.notAfterLocalDay;
    var certIss = cert.issuerOrganization;

    // replace variable names in format string with values
    label = label
      .replace(/\$CERTORG/g,    certOrg  ? certOrg : '?')
      .replace(/\$CERTCN/g,     certCn   ? certCn  : '?')
      .replace(/\$CERTALG/g,    certAlg  ? certAlg : '?')
      .replace(/\$CERTSIZE/g,   certSize ? certSize: '?')
      .replace(/\$CERTHASH/g,   certHash ? certHash: '?')
      .replace(/\$CERTISSUED/g, certFrom ? certFrom: '?')
      .replace(/\$CERTEXP/g,    certExp  ? certExp : '?')
      .replace(/\$CERTISSUER/g, certIss  ? certIss : '?');

    return label;
  };

  var updateCipher = function() {
    hideIdentityPopup();

    var currentBrowser = gBrowser.selectedBrowser;
    var panelLabel = null;
    var hidden = true;

    var ui = currentBrowser.securityUI;
    if (ui instanceof Ci.nsISecureBrowserUI) {
      var status = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      var isPartial = (ui.state & Ci.nsIWebProgressListener.STATE_IS_BROKEN);

      if (status instanceof Ci.nsISSLStatus) {
        panelLabel = formatLabel(status);
        hidden = !(panelLabel && (!isPartial || prefs.show_partial));
        populateCertChain(status);
      }
    }

    cfPanel.label = cfButton.label = panelLabel;
    cfPanel.hidden  = hidden || !prefs.show_panel;
    cfButton.hidden = hidden || !prefs.show_button;
  };

  // unused functions must be defined
  var updateListener = {
    onStateChange:    function(){},
    onProgressChange: function(){},
    onLocationChange: function(){},
    onStatusChange:   function(){},
    onSecurityChange: function(webProgress, request, state) { updateCipher(); }
  };

  // exposed methods
  return {
    onLoad: function() {
      cfToggle = document.getElementById('cipherfox-toggle-rc4');
      cfPanel  = document.getElementById('cipherfox-panel');
      cfButton = document.getElementById('cipherfox-button');
      cfCerts  = document.getElementById('cipherfox-certs');
      cfBCerts = document.getElementById('cipherfox-button-certs');
      cfPSep   = document.getElementById('cipherfox-prefs-seperator');

      // don't autohide the identity-popup
      var moreInfo = document.getElementById('identity-popup-more-info-button');
      if (moreInfo instanceof XULElement) {
        moreInfo.removeAttribute('onblur');
        moreInfo.addEventListener('command', hideIdentityPopup, false);
      }

      cfCerts.addEventListener('popupshowing', function() {
        cfPanel.setAttribute('popupopen', true);
      }, false);

      cfCerts.addEventListener('popuphiding', function() {
        cfPanel.removeAttribute('popupopen');
      }, false);

      // quick RC4 toggle
      cfToggle.addEventListener('command', toggleRC4, false);

      // keep the identity-box 'open'
      cfBCerts.addEventListener('popuphidden', function(e) {
        e.stopPropagation();
      }, false);

      prefService.addObserver('extensions.cipherfox.', this, false);
      loadPrefs();

      // only modify RC4 prefs if the user has disabled RC4
      if (prefs.disable_rc4) { setRC4(); }

      gBrowser.addProgressListener(updateListener);
    },

    onUnload: function() {
      prefService.removeObserver('extensions.cipherfox.', this);
      gBrowser.removeProgressListener(updateListener);
    },

    // update state when prefs change
    observe: function(subject, topic, data) {
      if (topic === 'nsPref:changed') {
        loadPrefs();
        updateCipher();
        if (data === 'extensions.cipherfox.disable_rc4') { setRC4(); }
      }
    },

    // Qualys SSL Labs Server Test
    testDomain: function() {
      gBrowser.addTab('https://www.ssllabs.com/ssldb/analyze.html?d='
                      + gBrowser.contentDocument.domain);
    }
  };
})();
