#!/usr/bin/env node

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { spawn } from 'node-pty';
import { WebSocketServer } from 'ws';

const sessionName = 'HESTIASID';
const hostname = execSync('hostname', { silent: true }).toString().trim();
const systemIPs = JSON.parse(
	execSync(`${process.env.HESTIA}/bin/v-list-sys-ips json`, { silent: true }).toString(),
);
const { config } = JSON.parse(
	execSync(`${process.env.HESTIA}/bin/v-list-sys-config json`, { silent: true }).toString(),
);


function extractSessionID(cookieHeader) {
	if (!cookieHeader) return null;
	const match = cookieHeader.match(new RegExp(`${sessionName}=([^;]+)`));
	return match ? match[1] : null;
}

function isValidSessionID(id) {
	return typeof id === 'string' && /^[a-zA-Z0-9,-]{22,256}$/.test(id);
}

function parsePhpSession(raw) {
	const result = {};
	const regex = /([a-zA-Z_]+)\|s:(\d+):"([^"]*)"/g;
	let match;
	while ((match = regex.exec(raw)) !== null) {
		const [, key, declaredLen, value] = match;
		if (parseInt(declaredLen, 10) === Buffer.byteLength(value)) {
			result[key] = value;
		}
	}
	return result;
}

function isValidUnixUsername(name) {
	return typeof name === 'string' && /^[a-z_][a-z0-9_-]{0,31}$/.test(name);
}

const wss = new WebSocketServer({
	port: parseInt(config.WEB_TERMINAL_PORT, 10),
	verifyClient: (info, cb) => {
		const cookie = info.req.headers.cookie;
		const sessionID = extractSessionID(cookie);

		if (!sessionID || !isValidSessionID(sessionID)) {
			cb(false, 401, 'Unauthorized');
			return;
		}

		const origin = info.origin || info.req.headers.origin;
		let matches = origin === `https://${hostname}:${config.BACKEND_PORT}`;

		if (!matches) {
			for (const ip of Object.keys(systemIPs)) {
				if (origin === `https://${ip}:${config.BACKEND_PORT}`) {
					matches = true;
					break;
				}
			}
		}

		if (matches) {
			cb(true);
			return;
		}
		cb(false, 403, 'Forbidden');
	},
});

wss.on('connection', (ws, req) => {
	const remoteIP = req.headers['x-real-ip'] || req.socket.remoteAddress;

	const sessionID = extractSessionID(req.headers.cookie);
	if (!sessionID || !isValidSessionID(sessionID)) {
		ws.close(1000, 'Invalid session.');
		return;
	}
	console.log(`New connection from ${remoteIP} (${sessionID})`);

	let session;
	try {
		const file = readFileSync(`${process.env.HESTIA}/data/sessions/sess_${sessionID}`);
		session = parsePhpSession(file.toString());
	} catch {
		console.error(`Invalid session ID ${sessionID}, refusing connection`);
		ws.close(1000, 'Your session has expired.');
		return;
	}

	if (!session.user) {
		console.error(`Malformed session ${sessionID}`);
		ws.close(1000, 'Invalid session data.');
		return;
	}

	const login = session.user;
	const impersonating = session.look || '';
	const username = impersonating.length > 0 ? impersonating : login;

	if (!isValidUnixUsername(username)) {
		console.error(`Invalid username "${username}", refusing connection`);
		ws.close(1000, 'Invalid user.');
		return;
	}

	const passwd = readFileSync('/etc/passwd').toString();
	const userline = passwd.split('\n').find((line) => line.startsWith(`${username}:`));
	if (!userline) {
		console.error(`User ${username} not found, refusing connection`);
		ws.close(1000, 'You are not allowed to access this server.');
		return;
	}
	const [, , uid, gid, , homedir, shell] = userline.split(':');

	if (parseInt(uid, 10) === 0) {
		console.error(`Root shell refused for session ${sessionID}`);
		ws.close(1000, 'Root terminal access is not allowed.');
		return;
	}

	if (shell.endsWith('nologin')) {
		console.error(`User ${username} has no shell, refusing connection`);
		ws.close(1000, 'You have no shell access.');
		return;
	}

	const pty = spawn(shell, [], {
		name: 'xterm-color',
		uid: parseInt(uid, 10),
		gid: parseInt(gid, 10),
		cwd: homedir,
		env: {
			SHELL: shell,
			TERM: 'xterm-color',
			USER: username,
			HOME: homedir,
			PWD: homedir,
			HESTIA: process.env.HESTIA,
		},
	});
	console.log(`New pty (${pty.pid}): ${shell} as ${username} (${uid}:${gid}) in ${homedir}`);

	pty.on('data', (data) => ws.send(data));

	ws.on('message', (data) => {
		if (data.length > 4096) return;
		pty.write(data);
	});

	pty.on('exit', () => {
		console.log(`Ended pty (${pty.pid})`);
		if (ws.readyState === ws.OPEN) {
			ws.close();
		}
	});

	ws.on('close', () => {
		console.log(`Ended connection from ${remoteIP} (${sessionID})`);
		pty.kill();
	});
});
