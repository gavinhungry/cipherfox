/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

CipherFox = (() => {
  'use strict';

  const Cc = Components.classes;
  const Ci = Components.interfaces;
  const Cu = Components.utils;

  const CertDb = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB);
  const CertDlg = Cc['@mozilla.org/nsCertificateDialogs;1'].getService(Ci.nsICertificateDialogs);
  const ClipboardHelper = Cc["@mozilla.org/widget/clipboardhelper;1"].getService(Ci.nsIClipboardHelper);
  const DirService = Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties);
  const PrefService = Cc['@mozilla.org/preferences-service;1'].getService(Ci.nsIPrefBranch2);
  const StringBundleService = Cc['@mozilla.org/intl/stringbundle;1'].getService(Ci.nsIStringBundleService);

  const UNKNOWN = '?'; // label to use for missing fields
  const CIPHERS = new RegExp([
    '_AES_', '_RC4_', '_3DES_', '_DES_', '_CAMELLIA_', '_RC2_', '_DES40_',
    '_FORTEZZA_', '_IDEA_', '_SEED_', '_GOST', '_NULL_', '_CHACHA20_'
  ].join('|'));

  Cu.import('resource://gre/modules/NetUtil.jsm');

  let prefs = {};
  let pipnss;

  // XUL DOM elements
  let cfPanel, cfButton, cfCerts, cfBCerts, cfPSep;

  let getOmniUri = path => {
    let omniPath = DirService.get('GreD', Ci.nsIFile);
    omniPath.appendRelativePath('omni.ja');

    return 'jar:file://' + omniPath.path.replace(/\\/g, '/') + '!' + Array.prototype.join.call(arguments, '');
  };

  let getFileContents = (uri, callback) => {
    try {
      NetUtil.asyncFetch(uri, (stream, result) => {
        if (!Components.isSuccessCode(result)) {
          callback(null);
        }

        let contents = NetUtil.readInputStreamToString(stream, stream.available());
        callback(contents);
      });
    } catch(err) {
      callback(null);
    }
  };

  let getPipnssStringBundle = callback => {
    getFileContents(getOmniUri('/chrome/chrome.manifest'), manifest => {
      let pipnssUri = '';
      let pipnss;

      if (manifest) {
        let pipnssLine = manifest.split('\n').find(str => {
          return str.indexOf('locale pipnss ') === 0;
        });

        if (pipnssLine) {
          let pipnssPath = pipnssLine.split(' ')[3];
          pipnssUri = getOmniUri('/chrome/', pipnssPath, 'pipnss.properties');
        }
      }

      try {
        pipnss = StringBundleService.createBundle(pipnssUri);
        pipnss.getSimpleEnumeration();
      } catch(err) {
        pipnss = StringBundleService.createBundle('chrome://pipnss/locale/pipnss.properties');
      }

      callback(pipnss);
    });
  };

  let getStringFromName = name => {
    try {
      return pipnss.GetStringFromName(name);
    } catch(err) {
      return null;
    }
  };

  let setElementBoolean = (el, attr, bool) => {
    if (!(el instanceof XULElement)) {
      return;
    }

    if (!bool) {
      el.removeAttribute(attr);
    } else {
      el.setAttribute(attr, true);
    }
  };

  let hideIdentityPopup = () => {
    try {
      gIdentityHandler.hideIdentityPopup();
    } catch(err) {}
  };

  // show dialog for cert in database
  let viewCertByDBKey = e => {
    hideIdentityPopup();

    let dbkey = e.target.getAttribute('dbkey');
    let cert = CertDb.findCertByDBKey(dbkey, null);
    CertDlg.viewCert(window, cert);
  };

  // get existing preferences
  let loadPrefs = () => {
    prefs.base_format   = PrefService.getCharPref('extensions.cipherfox.base_format');
    prefs.cert_format   = PrefService.getCharPref('extensions.cipherfox.cert_format');
    prefs.header_format = PrefService.getCharPref('extensions.cipherfox.header_format');
    prefs.show_builtin  = PrefService.getBoolPref('extensions.cipherfox.show_builtin');
    prefs.show_partial  = PrefService.getBoolPref('extensions.cipherfox.show_partial');
    prefs.show_panel    = PrefService.getBoolPref('extensions.cipherfox.show_panel');
    prefs.show_button   = PrefService.getBoolPref('extensions.cipherfox.show_button');
  };

  // get all certs and update
  let populateCertChain = status => {
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

    let serverCert = status.serverCert;
    if (serverCert instanceof Ci.nsIX509Cert) {
      let certChain = serverCert.getChain().enumerate();

      while (certChain.hasMoreElements()) {
        let next = certChain.getNext();
        let cert = next.QueryInterface(Ci.nsIX509Cert || Ci.nsIX509Cert2);

        let certItem = document.createElement('menuitem');

        if (cert.tokenName === 'Builtin Object Token' &&
            cert.certType === Ci.nsIX509Cert.CA_CERT) {
          if (!prefs.show_builtin) { continue; }
          certItem.setAttribute('builtin', true);
        }

        let label = formatLabel(cert);
        let dbkey = cert.dbKey.replace(/[\n\r\t]/g, '');

        // selecting a cert brings up details
        certItem.setAttribute('label', label);
        certItem.setAttribute('dbkey', dbkey);

        // add attributes for styling
        certItem.setAttribute('cert', true);
        if (!cfCerts.hasChildNodes()) {
          certItem.setAttribute('first', true);
        }

        certItem.addEventListener('command', viewCertByDBKey, false);

        let certItemB = certItem.cloneNode(false);
        certItemB.addEventListener('command', viewCertByDBKey, false);

        cfCerts.insertBefore(certItem, cfCerts.firstChild);
        if (cfBCerts instanceof XULElement) {
          cfBCerts.insertBefore(certItemB, cfPSep);
        }
      }
    }
  };

  let protocolString = v => {
    if (typeof v !== 'number' || isNaN(v)) {
      return null;
    }

    if (v === Ci.nsISSLStatus.SSL_VERSION_3) { return 'SSL 3.0'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1) { return 'TLS 1.0'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_1) { return 'TLS 1.1'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_2) { return 'TLS 1.2'; }
    if (v === Ci.nsISSLStatus.TLS_VERSION_1_3) { return 'TLS 1.3'; }
  };

  let formatLabel = (obj, format) => {
    let cert, label;

    if (obj instanceof Ci.nsISSLStatus) {
      cert = obj.serverCert;
      label = typeof format === 'string' ? format : prefs.base_format;

      let cipherName = obj.cipherName;
      let suiteMatch = CIPHERS.exec(cipherName);
      let protocol = protocolString(obj.protocolVersion); // Fx 36+

      let cipherSuite = obj.cipherSuite;

      // in Fx 25+, cipherName contains a full cipher suite
      if (suiteMatch) {
        cipherSuite = cipherName; // full cipher suite
        cipherName = suiteMatch[0].replace(/_/g, ''); // short cipher name
      } else {
        cipherName = cipherName.split('-')[0];
      }

      label = label
        .replace(/\$CIPHERALG/g, cipherName || UNKNOWN)
        .replace(/\$CIPHERSIZE/g, obj.secretKeyLength || UNKNOWN)
        .replace(/\$CIPHERSUITE/g, cipherSuite || UNKNOWN)
        .replace(/\$PROTOCOL/g, protocol || UNKNOWN);

    } else if (obj instanceof Ci.nsIX509Cert) {
      cert = obj;
      label = typeof format === 'string' ? format : prefs.cert_format;
    } else { return null; }

    let certDmp = Cc['@mozilla.org/security/nsASN1Tree;1'].createInstance(Ci.nsIASN1Tree);
    certDmp.loadASN1Structure(cert.ASN1Structure);

    let certOrg = cert.organization ? cert.organization : cert.commonName;
    let certCn  = cert.commonName   ? cert.commonName   : cert.organization;

    let certAlg;
    switch (certDmp.getDisplayData(11)) {
      case getStringFromName('CertDumpRSAEncr'):
        certAlg = 'RSA';
        break;
    }

    if (!certAlg) {
      switch (certDmp.getDisplayData(12)) {
        case getStringFromName('CertDumpECPublicKey'):
          certAlg = 'ECC';
          break;
        case getStringFromName('CertDumpAnsiX9DsaSignature'):
        case getStringFromName('CertDumpAnsiX9DsaSignatureWithSha1'):
          certAlg = 'DSA';
          break;
      }
    }

    let certSize, key, template;
    try {
      switch(certAlg) {
        case 'RSA':
          key = certDmp.getDisplayData(12).split('\n')[0];
          template = getStringFromName('CertDumpRSATemplate');
          break;

        case 'ECC':
          key = certDmp.getDisplayData(14).split('\n')[0];
          template = getStringFromName('CertDumpECTemplate');
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
        let discards = template.split('\n')[0].split('%S');
        discards.forEach(str => {
          key = key.replace(str, '');
        });

        certSize = key;
      }
    } catch(err) {}

    // look for hash type
    let certHash;
    let displayData = certDmp.getDisplayData(certDmp.rowCount-2);
    switch (displayData) {
      case getStringFromName('CertDumpMD2WithRSA'):
        certHash = 'MD2'; break;
      case getStringFromName('CertDumpMD5WithRSA'):
        certHash = 'MD5'; break;
      case getStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha1'):
      case getStringFromName('CertDumpSHA1WithRSA'):
        certHash = 'SHA1'; break;
      case getStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha224'):
        certHash = 'SHA224'; break;
      case getStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha256'):
      case getStringFromName('CertDumpSHA256WithRSA'):
        certHash = 'SHA256'; break;
      case getStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha384'):
      case getStringFromName('CertDumpSHA384WithRSA'):
        certHash = 'SHA384'; break;
      case getStringFromName('CertDumpAnsiX962ECDsaSignatureWithSha512'):
      case getStringFromName('CertDumpSHA512WithRSA'):
        certHash = 'SHA512';
    }

    // assume ECDSA OID
    if (!certHash) {
      // displayData: 'Object Identifier (1 2 840 10045 4 3 2)'
      let oidMatches = displayData.match(/\((.*)\)/);
      if (oidMatches && oidMatches.length > 1) {
        let oid = oidMatches[1];

        switch (oid) {
          case '1 2 840 10045 4 1':   certHash = 'SHA1';   break;
          case '1 2 840 10045 4 3 1': certHash = 'SHA224'; break;
          case '1 2 840 10045 4 3 2': certHash = 'SHA256'; break;
          case '1 2 840 10045 4 3 3': certHash = 'SHA384'; break;
          case '1 2 840 10045 4 3 4': certHash = 'SHA512'; break;
        }
      }
    }

    let certFrom = new Date(cert.validity.notBefore / 1000).toLocaleDateString();
    let certExp = new Date(cert.validity.notAfter / 1000).toLocaleDateString();
    let certIss = cert.issuerOrganization;

    // replace variable names in format string with values
    label = label
      .replace(/\$CERTORG/g,    certOrg  || UNKNOWN)
      .replace(/\$CERTCN/g,     certCn   || UNKNOWN)
      .replace(/\$CERTALG/g,    certAlg  || UNKNOWN)
      .replace(/\$CERTSIZE/g,   certSize || UNKNOWN)
      .replace(/\$CERTHASH/g,   certHash || UNKNOWN)
      .replace(/\$CERTISSUED/g, certFrom || UNKNOWN)
      .replace(/\$CERTEXP/g,    certExp  || UNKNOWN)
      .replace(/\$CERTISSUER/g, certIss  || UNKNOWN);

    return label;
  };

  let updateCipher = () => {
    hideIdentityPopup();

    let currentBrowser = gBrowser.selectedBrowser;
    let panelLabel = null;
    let headerLabel = null;
    let hidden = true;

    let ui = currentBrowser.securityUI;
    if (ui instanceof Ci.nsISecureBrowserUI) {
      let status = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      let isPartial = (ui.state & Ci.nsIWebProgressListener.STATE_IS_BROKEN);

      if (status instanceof Ci.nsISSLStatus) {
        panelLabel = formatLabel(status);
        headerLabel = formatLabel(status, prefs.header_format);
        hidden = !(panelLabel && (!isPartial || prefs.show_partial));
        populateCertChain(status);
      }
    }

    if (headerLabel) {
      let headerItem = document.createElement('menuitem');
      headerItem.setAttribute('disabled', true);
      headerItem.setAttribute('label', headerLabel);

      let headerItemB = headerItem.cloneNode(false);

      let sepItem = document.createElement('menuseparator');
      let sepItemB = sepItem.cloneNode(false);

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

  let updateListener = {
    onStateChange:    () => {},
    onProgressChange: () => {},
    onLocationChange: () => {},
    onStatusChange:   () => {},
    onSecurityChange: (webProgress, request, state) => updateCipher()
  };

  // exposed methods
  return {
    onLoad: () => {
      cfButton = document.getElementById('cipherfox-button');
      let footer = document.getElementById('identity-popup-securityView-footer');
      if (footer) {
        footer.appendChild(cfButton);
      }

      cfPanel  = document.getElementById('cipherfox-panel');
      cfCerts  = document.getElementById('cipherfox-certs');
      cfBCerts = document.getElementById('cipherfox-button-certs');
      cfPSep   = document.getElementById('cipherfox-prefs-seperator');

      // don't autohide the identity-popup
      let moreInfo = document.getElementById('identity-popup-more-info-button');
      if (moreInfo instanceof XULElement) {
        moreInfo.removeAttribute('onblur');
        moreInfo.addEventListener('command', hideIdentityPopup, false);
      }

      if (cfCerts instanceof XULElement) {
        cfCerts.addEventListener('popupshowing', () => {
          cfPanel.setAttribute('popupopen', true);
        }, false);

        cfCerts.addEventListener('popuphiding', () => {
          cfPanel.removeAttribute('popupopen');
        }, false);
      }

      // keep the identity-box 'open'
      if (cfBCerts instanceof XULElement) {
        cfBCerts.addEventListener('popuphidden', e => {
          e.stopPropagation();
        }, false);
      }

      PrefService.addObserver('extensions.cipherfox.', CipherFox, false);
      loadPrefs();

      getPipnssStringBundle(bundle => {
        pipnss = bundle;
        gBrowser.addProgressListener(updateListener);
      });
    },

    onUnload: () => {
      PrefService.removeObserver('extensions.cipherfox.', CipherFox);
      gBrowser.removeProgressListener(updateListener);
    },

    // update state when prefs change
    observe: (subject, topic, data) => {
      if (topic === 'nsPref:changed') {
        loadPrefs();
        updateCipher();
      }
    },

    copyCipherSuite: () => {
      let securityUI = gBrowser.selectedBrowser.securityUI;
      if (securityUI instanceof Ci.nsISecureBrowserUI) {
        let status = securityUI.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
        if (status instanceof Ci.nsISSLStatus) {
          ClipboardHelper.copyString(status.cipherSuite || status.cipherName);
        }
      }
    },

    // Qualys SSL Labs Server Test
    testDomain: () => {
      gBrowser.addTab('https://www.ssllabs.com/ssldb/analyze.html?d=' +
        (gBrowser.contentDocument ? gBrowser.contentDocument.domain : gBrowser.currentURI.host));
    }
  };
})();
