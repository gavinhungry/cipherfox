/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var CipherFox = (function() {
  'use strict';

  var Cc = Components.classes;
  var Ci = Components.interfaces;
  var Cu = Components.utils;

  Cu.import('resource://gre/modules/NetUtil.jsm');

  var certDb = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB);
  var certDlg = Cc['@mozilla.org/nsCertificateDialogs;1'].getService(Ci.nsICertificateDialogs);
  var clipboardHelper = Cc["@mozilla.org/widget/clipboardhelper;1"].getService(Ci.nsIClipboardHelper);
  var dirService = Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties);
  var prefService = Cc['@mozilla.org/preferences-service;1'].getService(Ci.nsIPrefBranch2);
  var stringBundleService = Cc['@mozilla.org/intl/stringbundle;1'].getService(Ci.nsIStringBundleService);

  var prefs = {};
  var pipnss;

  var unknown = '?'; // label to use for missing fields

  // ciphers from ciphersuites
  var ciphers = [
    '_AES_', '_RC4_', '_3DES_', '_DES_', '_CAMELLIA_', '_RC2_', '_DES40_',
    '_FORTEZZA_', '_IDEA_', '_SEED_', '_GOST', '_NULL_', '_CHACHA20_'
  ];

  var ciphersRe = new RegExp(ciphers.join('|'));

  // XUL DOM elements
  var cfPanel, cfButton, cfCerts, cfBCerts, cfPSep;

  var getOmniUri = function(path) {
    var omniPath = dirService.get('GreD', Ci.nsIFile);
    omniPath.appendRelativePath('omni.ja');

    return 'jar:file://' + omniPath.path.replace(/\\/g, '/') + '!' + Array.prototype.join.call(arguments, '');
  };

  var getFileContents = function(uri, callback) {
    try {
      NetUtil.asyncFetch(uri, function(stream, result) {
        if (!Components.isSuccessCode(result)) {
          callback(null);
        }

        var contents = NetUtil.readInputStreamToString(stream, stream.available());
        callback(contents);
      });
    } catch(err) {
      callback(null);
    }
  };

  var getPipnssStringBundle = function(callback) {
    getFileContents(getOmniUri('/chrome/chrome.manifest'), function(manifest) {
      var pipnssUri = '';
      var pipnss;

      if (manifest) {
        var pipnssLine = manifest.split('\n').find(function(str) {
          return str.indexOf('locale pipnss ') === 0;
        });

        if (pipnssLine) {
          var pipnssPath = pipnssLine.split(' ')[3];
          pipnssUri = getOmniUri('/chrome/', pipnssPath, 'pipnss.properties');
        }
      }

      try {
        pipnss = stringBundleService.createBundle(pipnssUri);
        pipnss.getSimpleEnumeration();
      } catch(err) {
        pipnss = stringBundleService.createBundle('chrome://pipnss/locale/pipnss.properties');
      }

      callback(pipnss);
    });
  };

  var setElementBoolean = function(el, attr, bool) {
    if (!(el instanceof XULElement)) {
      return;
    }

    if (!bool) {
      el.removeAttribute(attr);
    } else {
      el.setAttribute(attr, true);
    }
  };

  var hideIdentityPopup = function() {
    try {
      gIdentityHandler.hideIdentityPopup();
    } catch(err) {}
  };

  // show dialog for cert in database
  var viewCertByDBKey = function(e) {
    hideIdentityPopup();

    var dbkey = e.target.getAttribute('dbkey');
    var cert = certDb.findCertByDBKey(dbkey, null);
    certDlg.viewCert(window, cert);
  };

  // get existing preferences
  var loadPrefs = function() {
    prefs.base_format   = prefService.getCharPref('extensions.cipherfox.base_format');
    prefs.cert_format   = prefService.getCharPref('extensions.cipherfox.cert_format');
    prefs.header_format = prefService.getCharPref('extensions.cipherfox.header_format');
    prefs.show_builtin  = prefService.getBoolPref('extensions.cipherfox.show_builtin');
    prefs.show_partial  = prefService.getBoolPref('extensions.cipherfox.show_partial');
    prefs.show_panel    = prefService.getBoolPref('extensions.cipherfox.show_panel');
    prefs.show_button   = prefService.getBoolPref('extensions.cipherfox.show_button');
  };

  // get all certs and update
  var populateCertChain = function(status) {
    cfCerts.hidePopup();
    if (cfBCerts instanceof XULElement) {
      cfBCerts.hidePopup();
    }

    // remove old certs
    while(cfCerts.hasChildNodes()) {
      cfCerts.removeChild(cfCerts.firstChild);
    }

    if (cfBCerts instanceof XULElement) {
      while(cfBCerts.hasChildNodes() && cfBCerts.firstChild !== cfPSep) {
        cfBCerts.removeChild(cfBCerts.firstChild);
      }
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
        if (cfBCerts instanceof XULElement) {
          cfBCerts.insertBefore(certItemB, cfPSep);
        }
      }
    }
  };

  var protocolString = function(v) {
    if (typeof v !== 'number' || isNaN(v)) {
      return null;
    }

    if (v === Ci.nsISSLStatus.SSL_VERSION_3) { return 'SSL 3.0'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1) { return 'TLS 1.0'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_1) { return 'TLS 1.1'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_2) { return 'TLS 1.2'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_3) { return 'TLS 1.3'; }
  };

  var formatLabel = function(obj, format) {
    var cert, label;

    if (obj instanceof Ci.nsISSLStatus) {
      cert = obj.serverCert;
      label = typeof format === 'string' ? format : prefs.base_format;

      var cipherName = obj.cipherName;
      var suiteMatch = ciphersRe.exec(cipherName);
      var protocol = protocolString(obj.protocolVersion); // Fx 36+

      var cipherSuite = obj.cipherSuite;

      // in Fx 25+, cipherName contains a full cipher suite
      if (suiteMatch) {
        cipherSuite = cipherName; // full cipher suite
        cipherName = suiteMatch[0].replace(/_/g, ''); // short cipher name
      } else {
        cipherName = cipherName.split('-')[0];
      }

      label = label
        .replace(/\$CIPHERALG/g, cipherName || unknown)
        .replace(/\$CIPHERSIZE/g, obj.secretKeyLength || unknown)
        .replace(/\$CIPHERSUITE/g, cipherSuite || unknown)
        .replace(/\$PROTOCOL/g, protocol || unknown);

    } else if (obj instanceof Ci.nsIX509Cert) {
      cert = obj;
      label = typeof format === 'string' ? format : prefs.cert_format;
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
    } catch(err) {}

    // look for hash type
    var certHash;
    var displayData = certDmp.getDisplayData(certDmp.rowCount-2);
    switch (displayData) {
      case pipnss.GetStringFromName('CertDumpMD2WithRSA'):
        certHash = 'MD2'; break;
      case pipnss.GetStringFromName('CertDumpMD5WithRSA'):
        certHash = 'MD5'; break;
      case pipnss.GetStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha1'):
      case pipnss.GetStringFromName('CertDumpSHA1WithRSA'):
        certHash = 'SHA1'; break;
      case pipnss.GetStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha224'):
        certHash = 'SHA224'; break;
      case pipnss.GetStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha256'):
      case pipnss.GetStringFromName('CertDumpSHA256WithRSA'):
        certHash = 'SHA256'; break;
      case pipnss.GetStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha384'):
      case pipnss.GetStringFromName('CertDumpSHA384WithRSA'):
        certHash = 'SHA384'; break;
      case pipnss.GetStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha512'):
      case pipnss.GetStringFromName('CertDumpSHA512WithRSA'):
        certHash = 'SHA512';
    }

    // assume ECDSA OID
    if (!certHash) {
      // displayData: 'Object Identifier (1 2 840 10045 4 3 2)'
      var oidMatches = displayData.match(/\((.*)\)/);
      if (oidMatches && oidMatches.length > 1) {
        var oid = oidMatches[1];

        switch (oid) {
          case '1 2 840 10045 4 1':   certHash = 'SHA1';   break;
          case '1 2 840 10045 4 3 1': certHash = 'SHA224'; break;
          case '1 2 840 10045 4 3 2': certHash = 'SHA256'; break;
          case '1 2 840 10045 4 3 3': certHash = 'SHA384'; break;
          case '1 2 840 10045 4 3 4': certHash = 'SHA512'; break;
        }
      }
    }

    var certFrom = new Date(cert.validity.notBefore / 1000).toLocaleDateString();
    var certExp = new Date(cert.validity.notAfter / 1000).toLocaleDateString();
    var certIss = cert.issuerOrganization;

    // replace variable names in format string with values
    label = label
      .replace(/\$CERTORG/g,    certOrg  || unknown)
      .replace(/\$CERTCN/g,     certCn   || unknown)
      .replace(/\$CERTALG/g,    certAlg  || unknown)
      .replace(/\$CERTSIZE/g,   certSize || unknown)
      .replace(/\$CERTHASH/g,   certHash || unknown)
      .replace(/\$CERTISSUED/g, certFrom || unknown)
      .replace(/\$CERTEXP/g,    certExp  || unknown)
      .replace(/\$CERTISSUER/g, certIss  || unknown);

    return label;
  };

  var updateCipher = function() {
    hideIdentityPopup();

    var currentBrowser = gBrowser.selectedBrowser;
    var panelLabel = null;
    var headerLabel = null;
    var hidden = true;

    var ui = currentBrowser.securityUI;
    if (ui instanceof Ci.nsISecureBrowserUI) {
      var status = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      var isPartial = (ui.state & Ci.nsIWebProgressListener.STATE_IS_BROKEN);

      if (status instanceof Ci.nsISSLStatus) {
        panelLabel = formatLabel(status);
        headerLabel = formatLabel(status, prefs.header_format);
        hidden = !(panelLabel && (!isPartial || prefs.show_partial));
        populateCertChain(status);
      }
    }

    if (headerLabel) {
      var headerItem = document.createElement('menuitem');
      headerItem.setAttribute('disabled', true);
      headerItem.setAttribute('label', headerLabel);

      var headerItemB = headerItem.cloneNode(false);

      var sepItem = document.createElement('menuseparator');
      var sepItemB = sepItem.cloneNode(false);

      cfCerts.appendChild(sepItem);
      cfCerts.appendChild(headerItem);

      if (cfBCerts instanceof XULElement) {
        cfBCerts.insertBefore(headerItemB, cfBCerts.firstChild);
        cfBCerts.insertBefore(sepItemB, headerItemB.nextSibling);
      }
    }

    cfPanel.label = panelLabel;
    setElementBoolean(cfPanel, 'hidden', hidden || !prefs.show_panel);

    if (cfButton instanceof XULElement) {
      cfButton.setAttribute('label', panelLabel);
      setElementBoolean(cfButton, 'hidden', hidden || !prefs.show_button);
    }
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
      cfButton = document.getElementById('cipherfox-button');
      var footer = document.getElementById('identity-popup-securityView-footer');
      if (footer) {
        footer.appendChild(cfButton);
      }

      cfPanel  = document.getElementById('cipherfox-panel');
      cfCerts  = document.getElementById('cipherfox-certs');
      cfBCerts = document.getElementById('cipherfox-button-certs');
      cfPSep   = document.getElementById('cipherfox-prefs-seperator');

      // don't autohide the identity-popup
      var moreInfo = document.getElementById('identity-popup-more-info-button');
      if (moreInfo instanceof XULElement) {
        moreInfo.removeAttribute('onblur');
        moreInfo.addEventListener('command', hideIdentityPopup, false);
      }

      if (cfCerts instanceof XULElement) {
        cfCerts.addEventListener('popupshowing', function() {
          cfPanel.setAttribute('popupopen', true);
        }, false);

        cfCerts.addEventListener('popuphiding', function() {
          cfPanel.removeAttribute('popupopen');
        }, false);
      }

      // keep the identity-box 'open'
      if (cfBCerts instanceof XULElement) {
        cfBCerts.addEventListener('popuphidden', function(e) {
          e.stopPropagation();
        }, false);
      }

      prefService.addObserver('extensions.cipherfox.', this, false);
      loadPrefs();

      getPipnssStringBundle(function(bundle) {
        pipnss = bundle;
        gBrowser.addProgressListener(updateListener);
      });
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
      }
    },

    copyCipherSuite: function() {
      var securityUI = gBrowser.selectedBrowser.securityUI;
      if (securityUI instanceof Ci.nsISecureBrowserUI) {
        var status = securityUI.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
        if (status instanceof Ci.nsISSLStatus) {
          clipboardHelper.copyString(status.cipherSuite || status.cipherName);
        }
      }
    },

    // Qualys SSL Labs Server Test
    testDomain: function() {
      gBrowser.addTab('https://www.ssllabs.com/ssldb/analyze.html?d=' +
        (gBrowser.contentDocument ? gBrowser.contentDocument.domain : gBrowser.currentURI.host));
    }
  };
})();
