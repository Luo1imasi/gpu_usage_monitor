'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn, execFileSync} = require('node:child_process');
const {chromium} = require('playwright');

async function main() {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'monitor-browser-auth-'));
    const socket = net.createServer();
    await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
    const port = socket.address().port;
    await new Promise(resolve => socket.close(resolve));
    const origin = `http://localhost:${port}`;
    let server, browser;
    const fixtures = [];
    try {
        for (const [type, bits] of [['ed25519'], ['rsa', '2048'], ['ecdsa', '256'], ['ecdsa', '384'], ['ecdsa', '521']]) {
            for (const encrypted of [false, true]) {
                const filename = path.join(directory, `${type}-${bits || ''}-${encrypted}`);
                const password = encrypted ? 'browser-only-password-638219' : '';
                const args = ['-q', '-t', type, '-N', password, '-f', filename];
                if (bits) args.push('-b', bits);
                execFileSync('ssh-keygen', args);
                fixtures.push({filename, password, privateText: fs.readFileSync(filename, 'utf8')});
            }
        }
        const pemFilename = path.join(directory, 'rsa-pem');
        execFileSync('ssh-keygen', ['-q', '-t', 'rsa', '-b', '2048', '-m', 'PEM', '-N', 'pem-browser-password', '-f', pemFilename]);
        fixtures.push({filename: pemFilename, password: 'pem-browser-password', privateText: fs.readFileSync(pemFilename, 'utf8')});
        fs.writeFileSync(path.join(directory, 'user.txt'), fixtures.map(item => 'alice ' + fs.readFileSync(item.filename + '.pub', 'utf8').trim()).join('\n') + '\n');
        fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify({servers: []}));
        server = spawn('python3', ['-m', 'tests.browser_auth_server', directory, String(port)], {stdio: ['ignore', 'pipe', 'pipe']});
        let logs = '';
        server.stderr.on('data', chunk => { logs += chunk; });
        for (let attempt = 0; attempt < 100; attempt++) {
            try {
                if ((await fetch(origin + '/login')).ok) break;
            } catch (_) {}
            if (attempt === 99) throw new Error('Server did not start: ' + logs);
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        browser = await chromium.launch({headless: true, executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome', args: ['--no-sandbox']});
        for (const fixture of fixtures) {
            const context = await browser.newContext();
            const page = await context.newPage();
            const requests = [], errors = [];
            context.on('request', request => requests.push({url: request.url(), body: request.postData()}));
            page.on('pageerror', error => errors.push(error.message));
            await page.goto(origin + '/login');
            await page.locator('#private-key').setInputFiles(fixture.filename);
            await page.locator('#passphrase').fill(fixture.password);
            await page.locator('#submit').click();
            await Promise.race([
                page.waitForURL(origin + '/', {timeout: 90000}),
                page.waitForFunction(() => {
                    const status = document.querySelector('#status');
                    const button = document.querySelector('#submit');
                    return status && button && !button.disabled && status.textContent && status.textContent !== '正在验证…';
                }, {timeout: 90000}).then(() => { throw new Error('Login failed'); })
            ]).catch(async error => {
                throw new Error(path.basename(fixture.filename) + ': ' + await page.locator('#status').textContent() + '; ' + errors.join('; '));
            });
            assert.deepEqual(errors, []);
            const posts = requests.filter(request => request.body);
            assert.equal(posts.filter(request => request.url.endsWith('/api/auth/challenge')).length, 1);
            assert.equal(posts.filter(request => request.url.endsWith('/api/auth/verify')).length, 1);
            for (const request of requests) {
                assert.ok(request.url.startsWith(origin), 'Unexpected external request');
                const content = request.url + (request.body || '');
                assert.ok(!content.includes('PRIVATE KEY'), 'Private key header transmitted');
                assert.ok(!content.includes(fixture.privateText), 'Private key transmitted');
                if (fixture.password) assert.ok(!content.includes(fixture.password), 'Password transmitted');
            }
            for (const request of posts) {
                if (request.url.endsWith('/api/auth/challenge')) assert.deepEqual(Object.keys(JSON.parse(request.body)).sort(), ['key_id']);
                if (request.url.endsWith('/api/auth/verify')) assert.deepEqual(Object.keys(JSON.parse(request.body)).sort(), ['challenge_id', 'signature']);
            }
            const api = await context.request.get(origin + '/api/gpu');
            assert.equal(api.status(), 200);
            assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
            if (fixture === fixtures[0]) {
                for (const [width, height] of [[1280, 800], [390, 844]]) {
                    await page.setViewportSize({width, height});
                    await page.goto(origin + '/login');
                    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
                    await page.screenshot({path: path.join(directory, `login-${width}.png`)});
                }
                await page.route('**/login-assets/login-worker.js', async route => {
                    const response = await route.fetch();
                    await route.fulfill({response, body: (await response.text()) +
                        "\nfetch('/api/gpu').then(() => self.postMessage({blocked: false})).catch(() => self.postMessage({blocked: true}));"});
                });
                const workerBlocked = await page.evaluate(() => new Promise(resolve => {
                    const worker = new Worker('/login-assets/login-worker.js');
                    worker.onmessage = ({data}) => { worker.terminate(); resolve(data.blocked); };
                }));
                assert.ok(workerBlocked);
                await page.unroute('**/login-assets/login-worker.js');
            }
            await page.goto(origin + '/');
            await page.locator('#logout').click();
            await page.waitForURL(origin + '/login');
            assert.equal((await context.request.get(origin + '/api/gpu')).status(), 401);
            await context.close();
            process.stdout.write(`PASS ${path.basename(fixture.filename)}\n`);
        }
        const context = await browser.newContext();
        const page = await context.newPage();
        await page.goto(origin + '/login');
        await page.locator('#private-key').setInputFiles(fixtures[1].filename);
        await page.locator('#passphrase').fill('wrong-password');
        await page.locator('#submit').click();
        await page.waitForFunction(() => !document.querySelector('#submit').disabled);
        assert.match(await page.locator('#status').textContent(), /无法读取私钥/);
        assert.equal(await page.locator('#passphrase').inputValue(), '');
        await context.close();
        process.stdout.write(`Screenshots: ${directory}\n`);
    } finally {
        if (browser) await browser.close();
        if (server) {
            server.kill();
            await new Promise(resolve => server.once('exit', resolve));
        }
        // Keep only screenshots; remove every generated private key and login database.
        for (const filename of fs.readdirSync(directory)) {
            if (!filename.endsWith('.png')) fs.rmSync(path.join(directory, filename), {force: true});
        }
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
