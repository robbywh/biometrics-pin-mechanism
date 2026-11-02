// SEC-067 / SEC-006 / SEC-034: Android hardening.
//  - dataExtractionRules + fullBackupContent exclude everything (no secure prefs in cloud backup or device transfer)
//  - main manifest: usesCleartextTraffic=false
//  - debug manifest (src/debug/AndroidManifest.xml): usesCleartextTraffic=true (dev client talking to the LAN mock)
const { withAndroidManifest, withDangerousMod } = require('expo/config-plugins');
const fs = require('fs');
const path = require('path');

const EXTRACTION = `<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" />
    <exclude domain="file" />
    <exclude domain="database" />
    <exclude domain="sharedpref" />
    <exclude domain="external" />
  </cloud-backup>
  <device-transfer>
    <exclude domain="root" />
    <exclude domain="file" />
    <exclude domain="database" />
    <exclude domain="sharedpref" />
    <exclude domain="external" />
  </device-transfer>
</data-extraction-rules>
`;
const FULL_BACKUP = `<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
  <exclude domain="root" />
  <exclude domain="file" />
  <exclude domain="database" />
  <exclude domain="sharedpref" />
  <exclude domain="external" />
</full-backup-content>
`;
const DEBUG_MANIFEST = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:tools="http://schemas.android.com/tools">
  <application android:usesCleartextTraffic="true" tools:targetApi="28" tools:replace="android:usesCleartextTraffic" />
</manifest>
`;

module.exports = function withAndroidHardening(config) {
  config = withAndroidManifest(config, (c) => {
    const app = c.modResults.manifest.application[0];
    app.$['android:allowBackup'] = 'false';
    app.$['android:usesCleartextTraffic'] = 'false';
    app.$['android:dataExtractionRules'] = '@xml/data_extraction_rules';
    app.$['android:fullBackupContent'] = '@xml/full_backup_content';
    // dev-launcher adds SYSTEM_ALERT_WINDOW to the main manifest; keep it out of release builds (the debug manifest re-adds it).
    const m = c.modResults.manifest;
    m['uses-permission'] = (m['uses-permission'] ?? []).filter((p) => p.$['android:name'] !== 'android.permission.SYSTEM_ALERT_WINDOW');
    m['uses-permission'].push({ $: { 'android:name': 'android.permission.SYSTEM_ALERT_WINDOW', 'tools:node': 'remove' } });
    return c;
  });
  return withDangerousMod(config, [
    'android',
    async (c) => {
      const root = c.modRequest.platformProjectRoot;
      const xmlDir = path.join(root, 'app/src/main/res/xml');
      fs.mkdirSync(xmlDir, { recursive: true });
      fs.writeFileSync(path.join(xmlDir, 'data_extraction_rules.xml'), EXTRACTION);
      fs.writeFileSync(path.join(xmlDir, 'full_backup_content.xml'), FULL_BACKUP);
      const dbg = path.join(root, 'app/src/debug');
      fs.mkdirSync(dbg, { recursive: true });
      const target = path.join(dbg, 'AndroidManifest.xml');
      // Merge into the template's debug manifest if present, otherwise write ours.
      if (fs.existsSync(target)) {
        let s = fs.readFileSync(target, 'utf8');
        if (!s.includes('usesCleartextTraffic')) {
          s = s.replace(/<application/, '<application android:usesCleartextTraffic="true" tools:replace="android:usesCleartextTraffic"');
          if (!s.includes('xmlns:tools')) s = s.replace(/<manifest/, '<manifest xmlns:tools="http://schemas.android.com/tools"');
          fs.writeFileSync(target, s);
        }
      } else {
        fs.writeFileSync(target, DEBUG_MANIFEST);
      }
      return c;
    },
  ]);
};
