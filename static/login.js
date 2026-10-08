'use strict';

const form = document.getElementById('login-form');
const fileInput = document.getElementById('private-key');
const passphraseInput = document.getElementById('passphrase');
const submit = document.getElementById('submit');
const status = document.getElementById('status');
let worker = null;
const picker = document.getElementById('file-picker');
const fileName = document.getElementById('file-name');
const passwordToggle = document.getElementById('toggle-passphrase');

function updateFilePicker() {
    const file = fileInput.files[0];
    fileName.textContent = file ? file.name : '选择 SSH 私钥文件';
    picker.classList.toggle('selected', Boolean(file));
}
fileInput.addEventListener('change', updateFilePicker);
passwordToggle.addEventListener('click', () => {
    const visible = passphraseInput.type === 'password';
    passphraseInput.type = visible ? 'text' : 'password';
    passwordToggle.setAttribute('aria-pressed', String(visible));
    passwordToggle.title = visible ? '隐藏密码' : '显示密码';
    passwordToggle.setAttribute('aria-label', passwordToggle.title);
    passwordToggle.innerHTML = visible ? '<i data-lucide="eye-off" aria-hidden="true"></i>' : '<i data-lucide="eye" aria-hidden="true"></i>';
    window.renderMonitorIcons();
});

function workerMessage(message) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), 90000);
        worker.onmessage = ({data}) => {
            clearTimeout(timer);
            if (data.type === 'error') reject(new Error(data.error));
            else resolve(data);
        };
        worker.onerror = () => {
            clearTimeout(timer);
            reject(new Error('invalid_key'));
        };
        worker.postMessage(message);
    });
}

async function post(url, payload) {
    const response = await fetch(url, {
        method: 'POST', credentials: 'same-origin', redirect: 'error',
        headers: {'Content-Type': 'application/json', 'X-Monitor-Request': '1'},
        body: JSON.stringify(payload), signal: AbortSignal.timeout(15000)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'login_failed');
    return result;
}

const messages = {
    invalid_key: '无法读取私钥，请检查文件格式和私钥密码。',
    invalid_challenge: '登录请求无效或已过期，请重试。',
    invalid_signature: '签名验证失败或请求已过期，请重试。',
    key_not_registered: '此密钥没有登记，请联系管理员。',
    too_many_attempts: '登录尝试过于频繁，请稍后再试。',
    invalid_origin: '网站代理配置异常，请联系管理员检查 HTTPS 转发配置。',
    invalid_request: '登录请求格式异常，请刷新页面后重试。',
    timeout: '处理超时，请重试。'
};

form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!window.isSecureContext) {
        status.textContent = '请通过 HTTPS 访问，或在本机使用 localhost。';
        return;
    }
    if (!fileInput.files[0] || fileInput.files[0].size > 65536) {
        status.textContent = '请选择不超过 64 KiB 的 SSH 私钥文件。';
        return;
    }
    submit.disabled = true;
    status.classList.add('pending');
    form.setAttribute('aria-busy', 'true');
    status.textContent = '正在验证…';
    try {
        worker = new Worker('/login-assets/login-worker.js');
        const loading = workerMessage({type: 'load', file: fileInput.files[0], passphrase: passphraseInput.value});
        passphraseInput.value = '';
        fileInput.value = '';
        updateFilePicker();
        const loaded = await loading;
        const challenge = await post('/api/auth/challenge', {key_id: loaded.key_id});
        const signed = await workerMessage({type: 'sign', message: challenge.message, challenge_id: challenge.challenge_id});
        await post('/api/auth/verify', {challenge_id: challenge.challenge_id, signature: signed.signature});
        window.location.replace('/');
    } catch (error) {
        status.classList.remove('pending');
        status.textContent = messages[error.message] || '登录失败，请检查网络后重试。';
    } finally {
        if (worker) worker.terminate();
        worker = null;
        passphraseInput.value = '';
        fileInput.value = '';
        updateFilePicker();
        passphraseInput.type = 'password';
        passwordToggle.setAttribute('aria-pressed', 'false');
        passwordToggle.title = '显示密码';
        passwordToggle.setAttribute('aria-label', '显示密码');
        passwordToggle.innerHTML = '<i data-lucide="eye" aria-hidden="true"></i>';
        window.renderMonitorIcons();
        form.removeAttribute('aria-busy');
        submit.disabled = false;
    }
});

window.addEventListener('pagehide', () => {
    if (worker) worker.terminate();
    passphraseInput.value = '';
    fileInput.value = '';
});
