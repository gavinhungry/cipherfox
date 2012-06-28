/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var cipherFox = {

  onLoad: function() {
    this.certDb  = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB);
    this.certDlg = Cc['@mozilla.org/nsCertificateDialogs;1'].getService(Ci.nsICertificateDialogs); 
    this.pipnss  = Cc['@mozilla.org/intl/stringbundle;1'].getService(Ci.nsIStringBundleService)
                  .createBundle('chrome://pipnss/locale/pipnss.properties');

    this.prefs = Cc['@mozilla.org/preferences-service;1'].getService(Ci.nsIPrefBranch2);

    // default RC4 settings
    this.rc4 = ['ecdh_ecdsa_rc4_128_sha', 'ecdh_rsa_rc4_128_sha', 'ecdhe_ecdsa_rc4_128_sha',
                'ecdhe_rsa_rc4_128_sha', 'rsa_1024_rc4_56_sha', 'rsa_rc4_128_md5',
                'rsa_rc4_128_sha', 'rsa_rc4_40_md5'];

    this.cfToggle = document.getElementById('cipherfox-toggle-rc4');
    this.cfPanel  = document.getElementById('cipherfox-panel');
    this.cfButton = document.getElementById('cipherfox-button');
    this.cfCerts  = document.getElementById('cipherfox-certs');
    this.cfBCerts = document.getElementById('cipherfox-button-certs');
    this.cfPSep   = document.getElementById('cipherfox-prefs-seperator');

    // don't autohide the identity-popup
    var moreInfo = document.getElementById('identity-popup-more-info-button');
    if (moreInfo instanceof XULElement) {
      moreInfo.removeAttribute('onblur');
      moreInfo.addEventListener('command', function() { this.hideIdentityPopup(); }, false);
    }

    // keep the identity-box 'open'
    this.cfBCerts.addEventListener('popuphidden', function(e) {
      e.stopPropagation();
    }, false);

    this.prefs.addObserver('extensions.cipherfox.', this, false);
    this.loadPrefs();

    if (this.disable_rc4) {
      this.setRC4();
    }

    // the other functions are needed here, but not used
    this.updateListener = {
      onStateChange:    function(a, b, c, d) {},
      onProgressChange: function(a, b, c, d, e, f) {},
      onLocationChange: function(a, b, c) {},
      onStatusChange:   function(a, b, c, d) {},
      onSecurityChange: function(webProgress, request, state) { cipherFox.updateCipher(); }
    };

    gBrowser.addProgressListener(this.updateListener, Ci.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
  },


  onUnload: function() {
    this.prefs.removeObserver('extensions.cipherfox.', this);
    gBrowser.removeProgressListener(this.updateListener);
  },


  observe: function(subject, topic, data) {
    if (topic == 'nsPref:changed') {
      this.loadPrefs();
      this.updateCipher();

      if (data == 'extensions.cipherfox.disable_rc4') {
        this.setRC4();
      }
    }
  },


  // get existing preferences
  loadPrefs: function() {
    this.base_format  = this.prefs.getCharPref('extensions.cipherfox.base_format');
    this.cert_format  = this.prefs.getCharPref('extensions.cipherfox.cert_format');
    this.disable_rc4  = this.prefs.getBoolPref('extensions.cipherfox.disable_rc4');
    this.show_builtin = this.prefs.getBoolPref('extensions.cipherfox.show_builtin');
    this.show_partial = this.prefs.getBoolPref('extensions.cipherfox.show_partial');
    this.show_panel   = this.prefs.getBoolPref('extensions.cipherfox.show_panel');
    this.show_button  = this.prefs.getBoolPref('extensions.cipherfox.show_button');

    // set RC4 status and menuitem
    this.rc4Enabled = !this.disable_rc4;
    this.cfToggle.setAttribute('hidden', this.rc4Enabled);
    this.cfToggle.setAttribute('checked', this.rc4Enabled);
  },


  updateCipher: function() {
    this.hideIdentityPopup();
  
    var currentBrowser = gBrowser.selectedBrowser;
    var panelLabel = null;
    var hidden = true;

    var ui = currentBrowser.securityUI;
    if (ui instanceof Ci.nsISecureBrowserUI) {
      var status = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      var isPartial = (ui.state & Ci.nsIWebProgressListener.STATE_IS_BROKEN);

      if (status instanceof Ci.nsISSLStatus) {
        panelLabel = this.formatLabel(status);
        hidden = !(panelLabel && (!isPartial || this.show_partial));
        this.populateCertChain(status);
      }
    }

    this.cfPanel.label  = this.cfButton.label = panelLabel;
    this.cfPanel.hidden  = hidden || !this.show_panel;
    this.cfButton.hidden = hidden || !this.show_button;
  },


  // get all certs and update
  populateCertChain: function(status) {

    // remove old certs
    while(this.cfCerts.hasChildNodes()) {
      this.cfCerts.removeChild(this.cfCerts.firstChild);
    }

    while(this.cfBCerts.hasChildNodes() && this.cfBCerts.firstChild != this.cfPSep) {
      this.cfBCerts.removeChild(this.cfBCerts.firstChild);
    }

    var serverCert = status.serverCert;
    if (serverCert instanceof Ci.nsIX509Cert) {
      var certChain = serverCert.getChain().enumerate();

      while (certChain.hasMoreElements()) {
        var cert = certChain.getNext().QueryInterface(Ci.nsIX509Cert2);
        var certItem = document.createElement('menuitem');

        if (cert.tokenName == 'Builtin Object Token' && cert.certType == Ci.nsIX509Cert.CA_CERT) {
          if (!this.show_builtin) continue; 
          certItem.setAttribute('builtin', true);
        }

        var label = this.formatLabel(cert);
        var dbkey = cert.dbKey.replace(/[\n\r\t]/g, '');

        // selecting a cert brings up details
        certItem.setAttribute('label', label);
        certItem.setAttribute('dbkey', dbkey);

        // add attributes for styling
        certItem.setAttribute('cert', true);
        if (!this.cfCerts.hasChildNodes()) {
          certItem.setAttribute('first', true);
        }

        certItem.addEventListener('command', function(e) {
          cipherFox.viewCertByDBKey(e);
        }, false);

        var certItemB = certItem.cloneNode(false);
        certItemB.addEventListener('command', function(e) {
          cipherFox.viewCertByDBKey(e);
        }, false);

        this.cfCerts.insertBefore(certItem, this.cfCerts.firstChild);
        this.cfBCerts.insertBefore(certItemB, this.cfPSep);
      }
    }
  },


  formatLabel: function(obj) {
    var cert, label;

    if (obj instanceof Ci.nsISSLStatus) {
      cert = obj.serverCert;
      label = this.base_format
        .replace(/\$CIPHERALG/g,  obj.cipherName.split('-')[0])
        .replace(/\$CIPHERSIZE/g, obj.secretKeyLength);
    } else if (obj instanceof Ci.nsIX509Cert) {
        cert = obj;
        label = this.cert_format;
      } else return null;

    var certDmp = Cc['@mozilla.org/security/nsASN1Tree;1'].createInstance(Ci.nsIASN1Tree);
    certDmp.loadASN1Structure(cert.ASN1Structure);

    var certOrg = cert.organization ? cert.organization : cert.commonName;
    var certCn  = cert.commonName   ? cert.commonName   : cert.organization;

    var certAlg;
    switch (certDmp.getDisplayData(11)) {
      case this.pipnss.GetStringFromName('CertDumpRSAEncr'): certAlg = 'RSA'; break;
    }

    if (!certAlg) {
      switch (certDmp.getDisplayData(12)) {
        case this.pipnss.GetStringFromName('CertDumpAnsiX9DsaSignature'):
        case this.pipnss.GetStringFromName('CertDumpAnsiX9DsaSignatureWithSha1'): certAlg = 'DSA';
      }
    }

    var certSize;
    try {
      if (certAlg == 'RSA') {
        certSize = certDmp.getDisplayData(12).split("\n")[0].replace(/\D/g, '');
      } else if (certAlg == 'DSA') {
          var key = certDmp.getDisplayData(14);
          key = key.replace(key.split(/\n/)[0],'').replace(/\n|(\s$)/g, '').split(/\s/);
          if (key[0] == '02' && key[1] == '81') key.splice(0,3);
          if (key[0] == '00') key.splice(0,1);
          certSize = (8 * key.length);
        }
    } catch(e) {}

    // look for hash type
    var certHash;
    switch (certDmp.getDisplayData(certDmp.rowCount-2)) {
      case this.pipnss.GetStringFromName('CertDumpMD2WithRSA'):    certHash = 'MD2';    break;
      case this.pipnss.GetStringFromName('CertDumpMD5WithRSA'):    certHash = 'MD5';    break;
      case this.pipnss.GetStringFromName('CertDumpSHA1WithRSA'):   certHash = 'SHA1';   break;
      case this.pipnss.GetStringFromName('CertDumpSHA256WithRSA'): certHash = 'SHA256'; break;
      case this.pipnss.GetStringFromName('CertDumpSHA384WithRSA'): certHash = 'SHA384'; break;
      case this.pipnss.GetStringFromName('CertDumpSHA512WithRSA'): certHash = 'SHA512';
    }

    var certExp = cert.validity.notAfterLocalDay;
    var certIss = cert.issuerOrganization;

    // replace variable names in format string with values
    label = label
      .replace(/\$CERTORG/g,    certOrg ? certOrg : '?')
      .replace(/\$CERTCN/g,     certCn  ? certCn  : '?')
      .replace(/\$CERTALG/g,    certAlg ? certAlg : '?')
      .replace(/\$CERTSIZE/g,   certSize? certSize: '?')
      .replace(/\$CERTHASH/g,   certHash? certHash: '?')
      .replace(/\$CERTEXP/g,    certExp ? certExp : '?')
      .replace(/\$CERTISSUER/g, certIss ? certIss : '?');

    return label;
  },


  // show dialog for cert in database
  viewCertByDBKey: function(e) {
    var dbkey = e.target.getAttribute('dbkey');  
    var cert = this.certDb.findCertByDBKey(dbkey, null);
    this.certDlg.viewCert(window, cert);
  },


  toggleRC4: function() {
    this.rc4Enabled = !this.rc4Enabled;
    this.cfToggle.setAttribute('checked', this.rc4Enabled);
    this.setRC4();
  },


  setRC4: function() {
    for (var i = 0; i < this.rc4.length; i++) {
      if (this.rc4Enabled) {
        try {
          this.prefs.clearUserPref('security.ssl3.' + this.rc4[i]);
        } catch(e) {}
      }

      else {
        this.prefs.setBoolPref('security.ssl3.' + this.rc4[i], false);
      }
    }
  },


  hideIdentityPopup: function() {
    gIdentityHandler.hideIdentityPopup();
  },


  testDomain: function() {
    gBrowser.addTab('https://www.ssllabs.com/ssldb/analyze.html?d='
                   + gBrowser.contentDocument.domain);
  }
};
