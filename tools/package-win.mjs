import { mkdir, cp, copyFile, writeFile, rm, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { basename, dirname, join, relative, resolve } from 'node:path';
import {
  sourceDigest,
  windowsSourceDigest,
  includeDictionaryPath,
  assertReleaseArtifacts,
  listCompiledScripts,
  writeSha256Sidecar,
  verifySha256Sidecar,
  fileSha256,
} from './release-integrity.mjs';
import { buildInfoPayload, describeValidationScope, resolvePackagingScope } from './release-scope.mjs';
import { scanDirectoryForPrivacy } from './check-privacy.mjs';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));

/** Filters Finder/Explorer metadata and asset attribution manifests out of packaged resources. */
export function includePackagedWinAssetPath(relativePath) {
  const normalized = String(relativePath).replaceAll('\\', '/');
  const parts = normalized.split('/');
  if (parts.includes('.DS_Store') || parts.includes('Thumbs.db') || parts.includes('desktop.ini')) return false;
  if (normalized === 'model-icons/sources.json' || normalized === 'assets/model-icons/sources.json') return false;
  return true;
}

/** Computes a strictly bounded numeric build number from a three-part semver string. */
export function computeWinBuildNumber(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(version ?? '').trim());
  if (!match) {
    throw new Error(`无效的应用版本号，无法生成构建号：${String(version)}`);
  }
  const [, majorText, minorText, patchText] = match;
  const major = Number(majorText);
  const minor = Number(minorText);
  const patch = Number(patchText);
  if (minor > 99 || patch > 99) {
    throw new Error(`版本号超出构建号两位段上限（minor/patch <= 99）：${version}`);
  }
  return major * 10000 + minor * 100 + patch;
}

/** Keep npm and Cargo on SemVer while supporting a Windows product revision. */
export function resolveWindowsReleaseVersion({ version, windowsReleaseVersion = version }) {
  const match = /^(\d+\.\d+\.\d+)(?:\.(\d+))?$/.exec(windowsReleaseVersion);
  if (!match || match[1] !== version || windowsReleaseVersion.split('.').some(part => Number(part) > 65535)) {
    throw new Error(`无效的 Windows 发布版本：${windowsReleaseVersion}`);
  }
  return windowsReleaseVersion;
}

export function resolveWindowsPackagePaths({
  projectRoot = root,
  version,
  arch = process.arch,
}) {
  const outputDir = join(projectRoot, '成品');
  const stageDir = join(projectRoot, 'build', 'win-stage');
  const appDir = join(stageDir, 'GravityBox');
  const resourcesDir = join(appDir, 'resources');
  const zipPath = join(outputDir, `GravityBox-${version}-win-${arch}.zip`);
  const installerPath = join(outputDir, `GravityBox-${version}-win-${arch}-setup.exe`);
  return {
    outputDir,
    stageDir,
    appDir,
    resourcesDir,
    zipPath,
    sidecarPath: `${zipPath}.sha256`,
    installerPath,
    installerSidecarPath: `${installerPath}.sha256`,
  };
}

function resolveWindowsSystemRoot(env = process.env) {
  return env.SystemRoot?.trim() || env.WINDIR?.trim() || 'C:\\Windows';
}

export async function resolveMakensisPath(env = process.env, existsFn = existsSync) {
  const explicit = env.MAKENSIS_PATH?.trim();
  if (explicit && existsFn(explicit)) return explicit;

  const standardPaths = [
    'C:\\Program Files (x86)\\NSIS\\makensis.exe',
    'C:\\Program Files\\NSIS\\makensis.exe',
  ];
  for (const candidate of standardPaths) {
    if (existsFn(candidate)) return candidate;
  }

  try {
    const whereExe = join(resolveWindowsSystemRoot(env), 'System32', 'where.exe');
    const { stdout } = await run(whereExe, ['makensis'], { windowsHide: true });
    const first = stdout.split(/\r?\n/).map(line => line.trim()).find(line => line && existsFn(line));
    if (first) return first;
  } catch {
    // not in PATH
  }
  return null;
}

function npmExecSpec(args) {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && existsSync(npmExecPath)) {
    return { binary: process.execPath, args: [npmExecPath, ...args] };
  }
  return {
    binary: join(resolveWindowsSystemRoot(), 'System32', 'cmd.exe'),
    args: ['/d', '/s', '/c', 'npm', ...args],
  };
}

async function createZipFromDirectory(sourceDir, destZip) {
  await rm(destZip, { force: true, maxRetries: 3, retryDelay: 50 });
  const psScript = [
    'Add-Type -AssemblyName System.IO.Compression.FileSystem',
    '$src = $env:GB_ZIP_SRC',
    '$dst = $env:GB_ZIP_DST',
    '[System.IO.Compression.ZipFile]::CreateFromDirectory($src, $dst, [System.IO.Compression.CompressionLevel]::Optimal, $true, [System.Text.Encoding]::UTF8)',
  ].join('; ');
  const fallbackPowerShell = join(
    resolveWindowsSystemRoot(),
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const shellExe = existsSync('C:\\Program Files\\PowerShell\\7\\pwsh.exe')
    ? 'C:\\Program Files\\PowerShell\\7\\pwsh.exe'
    : fallbackPowerShell;
  await run(shellExe, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', psScript], {
    cwd: root,
    maxBuffer: 16e6,
    windowsHide: true,
    env: {
      ...process.env,
      GB_ZIP_SRC: sourceDir,
      GB_ZIP_DST: destZip,
    },
  });
}

async function buildSelfContainedNsisInstaller({
  version,
  arch,
  appDir,
  installerPath,
  iconPath,
  licensePath,
}) {
  const makensis = await resolveMakensisPath();
  if (!makensis) {
    throw new Error(
      '未找到 NSIS 编译器 makensis.exe。请在 Windows 上安装 NSIS（如 `winget install NSIS.NSIS` 或 `choco install nsis`）或设置环境变量 MAKENSIS_PATH 后重试。'
    );
  }
  const nsiScript = join(root, 'tools', 'gravitybox-win.nsi');
  if (!existsSync(nsiScript)) {
    throw new Error(`缺少 NSIS 打包脚本：${nsiScript}`);
  }
  if (!existsSync(iconPath)) {
    throw new Error(`缺少应用图标文件：${iconPath}`);
  }
  await rm(installerPath, { force: true, maxRetries: 3, retryDelay: 50 });

  // Compile to a pure-ASCII staging path first so makensis.exe never encounters non-ASCII
  // codepage issues on en-US (CP1252) runners when writing into the localized output folder.
  const asciiOutFile = join(dirname(appDir), basename(installerPath));
  await rm(asciiOutFile, { force: true, maxRetries: 3, retryDelay: 50 });

  const args = [
    '/INPUTCHARSET',
    'UTF8',
    '/V3',
    `/DAPP_VERSION=${version}`,
    `/DAPP_VI_VERSION=${version.split('.').length === 4 ? version : `${version}.0`}`,
    `/DAPP_ARCH=${arch}`,
    `/DSTAGE_DIR=${appDir}`,
    `/DOUT_FILE=${asciiOutFile}`,
    `/DAPP_ICON=${iconPath}`,
    `/DLICENSE_FILE=${licensePath}`,
    nsiScript,
  ];
  await run(makensis, args, {
    cwd: root,
    maxBuffer: 16e6,
    windowsHide: true,
  });

  if (!existsSync(asciiOutFile)) {
    throw new Error(`NSIS 编译完成但未生成安装包：${asciiOutFile}`);
  }
  await copyFile(asciiOutFile, installerPath);
  await rm(asciiOutFile, { force: true, maxRetries: 3, retryDelay: 50 });
}

async function main() {
  if (process.platform !== 'win32') {
    throw new Error('package-win 仅支持在 Windows 平台上执行');
  }
  if (!process.versions.node.startsWith('22.')) {
    throw new Error('请使用 Node 22 构建 Windows 自包含包');
  }

  const argv = process.argv.slice(2);
  const skipBuild = argv.includes('--skip-build');
  const withInstaller = argv.includes('--installer');
  const skipVerifyStamp = argv.includes('--skip-verify-stamp');

  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const baseVersion = pkg.version;
  const version = resolveWindowsReleaseVersion(pkg);
  const currentDigest = await sourceDigest(root);
  const currentWindowsDigest = await windowsSourceDigest(root);
  const { SUPPORTED_BUNDLES } = await import(pathToFileURL(join(root, 'dist', 'bundle.js')).href);
  const supportedVersions = [...SUPPORTED_BUNDLES.keys()];

  let verification;
  let scope;
  if (skipVerifyStamp) {
    process.stdout.write('[package-win] 警告：已启用 --skip-verify-stamp，仅限本地开发冒烟打包，不可用于正式发布\n');
    verification = {
      digest: currentDigest,
      windowsDigest: currentWindowsDigest,
      version: baseVersion,
      at: new Date().toISOString(),
      artifacts: null,
    };
    scope = {
      mode: 'full',
      targetAppVersions: supportedVersions,
      historicalUnverified: [],
    };
  } else {
    const verifiedPath = join(root, '.cache/verified-release.json');
    if (!existsSync(verifiedPath)) {
      throw new Error('未找到 .cache/verified-release.json，请先运行 npm run verify');
    }
    verification = JSON.parse(await readFile(verifiedPath, 'utf8'));
    if (
      verification.digest !== currentDigest ||
      verification.windowsDigest !== currentWindowsDigest ||
      verification.version !== baseVersion
    ) {
      throw new Error('源码已变化或未通过检查，请先运行 npm run verify');
    }
    await assertReleaseArtifacts(root, verification.artifacts);
    scope = resolvePackagingScope({ verification, argv, supportedVersions });
    process.stdout.write(`[package-win] ${describeValidationScope(scope)}\n`);
  }

  const winHelperManifest = join(root, 'windows', 'win-helper', 'Cargo.toml');
  const winHelperBin = join(root, 'windows', 'win-helper', 'target', 'release', 'gravitybox-win-helper.exe');
  const winAppDir = join(root, 'windows', 'app');
  const winAppCargo = join(winAppDir, 'src-tauri', 'Cargo.toml');
  const winDesktopBin = join(winAppDir, 'src-tauri', 'target', 'release', 'gravitybox-desktop.exe');

  if (!skipBuild || !existsSync(winHelperBin)) {
    process.stdout.write('[package-win] 构建 gravitybox-win-helper.exe (release)...\n');
    await run('cargo', ['build', '--release'], {
      cwd: dirname(winHelperManifest),
      maxBuffer: 16e6,
      windowsHide: true,
    });
  }
  if (!existsSync(winHelperBin)) {
    throw new Error(`缺少 Win32 Helper 产物：${winHelperBin}`);
  }

  if (!skipBuild || !existsSync(winDesktopBin)) {
    process.stdout.write('[package-win] 构建 Windows 桌面端前端与 Tauri release 二进制...\n');
    const feBuild = npmExecSpec(['run', 'build']);
    await run(feBuild.binary, feBuild.args, {
      cwd: winAppDir,
      maxBuffer: 16e6,
      windowsHide: true,
    });
    await run('cargo', ['build', '--release', '--manifest-path', winAppCargo], {
      cwd: winAppDir,
      maxBuffer: 16e6,
      windowsHide: true,
      env: { ...process.env, GRAVITYBOX_WINDOWS_RELEASE_VERSION: version },
    });
  }
  if (!existsSync(winDesktopBin)) {
    throw new Error(`缺少 Windows 桌面端产物：${winDesktopBin}`);
  }

  const { outputDir, stageDir, appDir, resourcesDir, zipPath, installerPath } = resolveWindowsPackagePaths({
    projectRoot: root,
    version,
    arch: process.arch,
  });

  await rm(stageDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 80 });
  await mkdir(join(resourcesDir, 'runtime'), { recursive: true });
  await mkdir(join(resourcesDir, 'core', 'dist'), { recursive: true });
  await mkdir(join(resourcesDir, 'icons'), { recursive: true });
  await mkdir(outputDir, { recursive: true });

  // 1. Desktop shell & top-level license files
  await copyFile(winDesktopBin, join(appDir, 'GravityBox.exe'));
  await copyFile(join(root, 'LICENSE'), join(appDir, 'LICENSE'));
  await copyFile(join(root, 'THIRD_PARTY_NOTICES.md'), join(appDir, 'THIRD_PARTY_NOTICES.md'));

  // 2. Native Win32 helper
  await copyFile(winHelperBin, join(resourcesDir, 'gravitybox-win-helper.exe'));

  // 3. Bundled portable Node 22 runtime
  await copyFile(process.execPath, join(resourcesDir, 'runtime', 'node.exe'));
  await copyFile(join(root, 'licenses', 'NODE-LICENSE'), join(resourcesDir, 'runtime', 'LICENSE'));

  // 4. Compiled backend scripts (strictly from listCompiledScripts, no stale files)
  for (const name of await listCompiledScripts(root)) {
    const dest = join(resourcesDir, 'core', 'dist', ...name.split('/'));
    await mkdir(join(dest, '..'), { recursive: true });
    await copyFile(join(root, 'dist', ...name.split('/')), dest);
  }
  await writeFile(join(resourcesDir, 'core', 'package.json'), JSON.stringify({ type: 'module', version: baseVersion }) + '\n', 'utf8');

  // 5. Dictionaries, model catalog, i18n, icons
  await cp(join(root, 'dict'), join(resourcesDir, 'core', 'dict'), {
    recursive: true,
    filter: source => includeDictionaryPath(join('dict', relative(join(root, 'dict'), source)).replaceAll('\\', '/')),
  });
  await copyFile(join(root, 'assets', 'model-catalog.json'), join(resourcesDir, 'model-catalog.json'));

  const filterAsset = source => includePackagedWinAssetPath(relative(join(root, 'assets'), source));
  await cp(join(root, 'assets', 'i18n'), join(resourcesDir, 'i18n'), { recursive: true, filter: filterAsset });
  await cp(join(root, 'assets', 'model-icons'), join(resourcesDir, 'model-icons'), { recursive: true, filter: filterAsset });
  await copyFile(join(root, 'assets', 'icons', 'menu-connected.png'), join(resourcesDir, 'icons', 'menu-connected.png'));
  const tauriIconIco = join(winAppDir, 'src-tauri', 'icons', 'icon.ico');
  const stagedIconIco = join(resourcesDir, 'icons', 'icon.ico');
  if (existsSync(tauriIconIco)) {
    await copyFile(tauriIconIco, stagedIconIco);
  }

  // 6. Build metadata
  const build = computeWinBuildNumber(baseVersion);
  const [winHelperSha256, desktopBinarySha256, nodeSha256] = await Promise.all([
    fileSha256(join(resourcesDir, 'gravitybox-win-helper.exe')),
    fileSha256(join(appDir, 'GravityBox.exe')),
    fileSha256(join(resourcesDir, 'runtime', 'node.exe')),
  ]);
  const buildInfo = {
    ...buildInfoPayload({ version, build, verification, scope, node: process.versions.node }),
    signing: 'unsigned',
    windowsSourceDigest: currentWindowsDigest,
    platform: 'win32',
    arch: process.arch,
    verified: !skipVerifyStamp,
    winHelperSha256,
    desktopBinarySha256,
    nodeSha256,
  };
  await writeFile(join(resourcesDir, 'build-info.json'), JSON.stringify(buildInfo, null, 2) + '\n', 'utf8');

  // 7. Privacy gate over staged bundle before archiving
  const bundlePrivacy = await scanDirectoryForPrivacy(appDir, {
    excludePrefixes: [
      'GravityBox.exe',
      'resources/gravitybox-win-helper.exe',
      'resources/runtime/',
    ],
  });
  if (bundlePrivacy.issues.length > 0) {
    const summary = bundlePrivacy.issues.map(i => `${i.file}:${i.line} [${i.code}] ${i.detail}`).join('\n');
    throw new Error(`Windows 应用包隐私检查未通过，已中止打包:\n${summary}`);
  }

  // 8. Archive portable zip & verify SHA-256 sidecar
  process.stdout.write(`[package-win] 生成便携压缩包：${zipPath}\n`);
  await createZipFromDirectory(appDir, zipPath);
  const sidecar = await writeSha256Sidecar(zipPath);
  const sidecarCheck = await verifySha256Sidecar(zipPath);
  if (sidecarCheck.hash !== sidecar.hash) {
    throw new Error('ZIP sha256 校验文件写入后复核不一致，已中止发布');
  }

  // 9. Self-contained NSIS installer (packs exact same verified appDir tree)
  const installers = [];
  if (withInstaller) {
    process.stdout.write(`[package-win] 构建自包含 NSIS 安装包：${installerPath}\n`);
    await buildSelfContainedNsisInstaller({
      version,
      arch: process.arch,
      appDir,
      installerPath,
      iconPath: existsSync(stagedIconIco) ? stagedIconIco : tauriIconIco,
      licensePath: join(appDir, 'LICENSE'),
    });
    const instSidecar = await writeSha256Sidecar(installerPath);
    const instVerify = await verifySha256Sidecar(installerPath);
    if (instVerify.hash !== instSidecar.hash) {
      throw new Error(`NSIS 安装包 sha256 校验失败：${installerPath}`);
    }
    installers.push({ path: installerPath, sha256: instVerify.hash, sha256File: instSidecar.sidecarPath });
  }

  console.log(JSON.stringify({
    appDir,
    zip: zipPath,
    sha256: sidecarCheck.hash,
    sha256File: sidecar.sidecarPath,
    winHelperSha256,
    desktopBinarySha256,
    nodeVersion: process.versions.node,
    platform: 'win32',
    arch: process.arch,
    verified: !skipVerifyStamp,
    installers,
    validationScope: {
      scope: scope.mode,
      targetAppVersions: scope.targetAppVersions,
      historicalUnverified: scope.historicalUnverified,
    },
  }, null, 2));
}

function isDirectEntry() {
  if (typeof process.argv[1] !== 'string') return false;
  if (process.platform === 'win32') {
    return resolve(process.argv[1]).toLowerCase() === resolve(fileURLToPath(import.meta.url)).toLowerCase();
  }
  return import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isDirectEntry()) {
  main().catch(error => {
    console.error(`[package-win] ${error?.message ?? error}`);
    process.exitCode = 1;
  });
}
