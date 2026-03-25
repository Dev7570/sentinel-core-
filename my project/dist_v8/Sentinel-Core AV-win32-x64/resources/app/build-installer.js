const electronInstaller = require('electron-winstaller');
const path = require('path');

async function buildInstaller() {
    console.log('Building Sentinel-Core AV Windows Installer...');
    console.log('This may take a minute as Squirrel compresses the application payload...');
    
    try {
        await electronInstaller.createWindowsInstaller({
            appDirectory: path.join(__dirname, 'dist_v8', 'Sentinel-Core AV-win32-x64'),
            outputDirectory: path.join(__dirname, 'dist', 'installer'),
            authors: 'Antigravity AI',
            exe: 'Sentinel-Core AV.exe',
            setupExe: 'Sentinel-Core-Setup-v8.exe',
            noMsi: true,
            description: 'Advanced Multi-Engine USB Antivirus',
        });
        console.log('Success! Installer created at: dist/installer/Sentinel-Core-Setup-v8.exe');
    } catch (e) {
        console.log(`Error building installer: ${e.message}`);
        process.exit(1);
    }
}

buildInstaller();
