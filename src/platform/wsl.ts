import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { join, win32 } from 'node:path';
import { promisify } from 'node:util';
import { pathsEqual } from './paths.js';
import { processTree } from './win32-helper.js';

const execFileAsync = promisify(execFile);
const LOG_TAIL_BYTES = 256 * 1024;
const CASCADE_DATABASE_NAME = /^([\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12})\.db$/i;

function systemWslPath(): string {
  return win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wsl.exe');
}

function launcherDistribution(command: string, version: string): string | undefined {
  const launcher = /^"?[^"\r\n]*?\\wsl\.exe"?\s+-d\s+(?:"([^"\r\n]+)"|([^"\r\n]+?))\s+--exec\s+sh\s+-c\s+/i.exec(command);
  const distribution = launcher?.[1] ?? launcher?.[2];
  if (!launcher || !distribution || !/^[\p{L}\p{N}][\p{L}\p{N}._ -]{0,127}$/u.test(distribution)) return undefined;
  const script = command.slice(launcher[0].length);
  const server = /^"?ANTIGRAVITY_VSCODE_HOST=1 exec \\?"?\$HOME\/\.antigravity-server\/bin\/([\d.]+)\/language_server(?=[\\"\s]|$)/.exec(script);
  return server?.[1] === version ? distribution : undefined;
}

function distributionForPort(log: string, port: number, version: string): string | undefined {
  let distribution: string | undefined;
  let currentPort: number | undefined;
  for (const line of log.split(/\r?\n/)) {
    const message = /^\[[^\]]+\] \[info\]\s+(.*)$/.exec(line)?.[1];
    if (!message) continue;
    if (message.startsWith('Starting app (')) {
      distribution = undefined;
      currentPort = undefined;
    } else if (message.startsWith('Spawning: ')) {
      distribution = launcherDistribution(message.slice('Spawning: '.length), version);
      currentPort = undefined;
    } else if (distribution) {
      const listener = /^(?:Local:\s+|\[Auto-Restart\] Port changed! Reloading all windows with URL: )https:\/\/127\.0\.0\.1:(\d{1,5})\/$/.exec(message.trimEnd());
      if (listener) currentPort = Number(listener[1]);
    }
  }
  return currentPort === port ? distribution : undefined;
}

async function readMainLogTail(profile: string): Promise<string> {
  const file = await open(join(profile, 'logs', 'main.log'), 'r');
  try {
    const { size } = await file.stat();
    const buffer = Buffer.alloc(Math.min(size, LOG_TAIL_BYTES));
    const offset = size - buffer.length;
    const { bytesRead } = await file.read(buffer, 0, buffer.length, offset);
    const tail = buffer.toString('utf8', 0, bytesRead);
    return offset > 0 ? tail.slice(tail.indexOf('\n') + 1) : tail;
  } finally {
    await file.close();
  }
}

// The two variable arguments are validated by Windows and passed as positional parameters.
// Return the verified guest user ID. Process command lines and credentials stay out of the probe output.
const INSPECT_LISTENER = `
set -eu
export LC_ALL=C
listeners=$(/usr/bin/ss -H -ltnp "sport = :$1")
pid=$(printf '%s\\n' "$listeners" | /usr/bin/awk -v port="$1" '
  $4 == "127.0.0.1:" port { ipv4 = 1 }
  $4 != "127.0.0.1:" port && $4 != "[::1]:" port { invalid = 1; exit }
  {
    if (!match($0, /pid=[0-9]+[,)]/)) { invalid = 1; exit }
    owner = substr($0, RSTART + 4, RLENGTH - 5)
    if ((pid && pid != owner) || substr($0, RSTART + RLENGTH) ~ /pid=[0-9]+/) { invalid = 1; exit }
    pid = owner
  }
  END { if (invalid || !ipv4 || !pid) exit 1; print pid }
')
home=$(/usr/bin/realpath -e -- "$HOME")
test "$(/usr/bin/readlink -- "/proc/$pid/exe")" = "$home/.antigravity-server/bin/$2/language_server"
/usr/bin/id -u
`;

async function inspectListener(wsl: string, distribution: string, port: number, version: string): Promise<string> {
  const { stdout } = await execFileAsync(wsl, ['--distribution', distribution, '--exec', '/bin/sh', '-c', INSPECT_LISTENER, 'gravitybox-wsl', String(port), version], {
    timeout: 3500, maxBuffer: 16 * 1024, windowsHide: true,
  });
  return stdout.trim();
}

export interface VerifiedWslPageService {
  kind: 'wsl';
  distribution: string;
  uid: string;
}

const LIST_CONVERSATIONS = `
set -eu
test "$(/usr/bin/id -u)" = "$1"
directory="$HOME/.gemini/antigravity/conversations"
if [ -d "$directory" ]; then
  /usr/bin/find -P "$directory" -maxdepth 1 -type f -size +0c -name '*.db' -printf '%f\\0'
fi
`;

/** Read only filenames. Antigravity itself reads each conversation through the verified page RPC. */
export async function listWslConversationIds(service: VerifiedWslPageService): Promise<string[]> {
  const { stdout } = await execFileAsync(systemWslPath(), [
    '--distribution', service.distribution, '--exec', '/bin/sh', '-c', LIST_CONVERSATIONS, 'gravitybox-wsl', service.uid,
  ], { timeout: 3000, maxBuffer: 2 * 1024 * 1024, windowsHide: true });
  return [...new Set(stdout.split('\0').flatMap(name => {
    const id = CASCADE_DATABASE_NAME.exec(name)?.[1];
    return id ? [id.toLowerCase()] : [];
  }))].sort();
}

/** Correlate the page port with the current desktop's WSL launcher and the guest's live listener. */
export async function verifyWslPageService(
  port: number,
  endpoint: { pid: number; profile: string; appVersion: string },
  deps = { readMainLogTail, processTree, inspectListener },
): Promise<VerifiedWslPageService | undefined> {
  const { pid, profile, appVersion } = endpoint;
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !/^\d+\.\d+\.\d+$/.test(appVersion)) return undefined;
  const wsl = systemWslPath();
  try {
    const distribution = distributionForPort(await deps.readMainLogTail(profile), port, appVersion);
    if (!distribution) return undefined;
    const launches = (await deps.processTree()).filter(entry => entry.ppid === pid &&
      pathsEqual(entry.exePath, wsl, 'win32') && launcherDistribution(entry.cmdLine, appVersion) === distribution);
    if (launches.length !== 1) return undefined;
    const uid = await deps.inspectListener(wsl, distribution, port, appVersion);
    return /^(?:0|[1-9]\d{0,9})$/.test(uid) ? { kind: 'wsl', distribution, uid } : undefined;
  } catch {
    return undefined;
  }
}
