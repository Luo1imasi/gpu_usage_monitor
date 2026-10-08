'use strict';

const {createIcons, Cpu, KeyRound, FileKey2, Eye, EyeOff, ArrowRight, LogOut,
    Server, Activity, Users, RefreshCw, UserPlus, Search, Download, ShieldCheck,
    ShieldOff, CheckCheck, ListChecks, X, LoaderCircle} = require('lucide');

window.renderMonitorIcons = () => createIcons({icons: {
    Cpu, KeyRound, FileKey2, Eye, EyeOff, ArrowRight, LogOut, Server, Activity,
    Users, RefreshCw, UserPlus, Search, Download, ShieldCheck, ShieldOff,
    CheckCheck, ListChecks, X, LoaderCircle
}});
const buttonIcons = {
    'check-ssh-key': 'search', 'add-user': 'user-plus', 'detect-users': 'search',
    'import-detected-users': 'download', 'refresh-access-matrix': 'refresh-cw',
    'configure-access': 'shield-check', 'revoke-access': 'shield-off',
    'select-missing-access': 'list-checks', 'select-configured-access': 'check-check',
    'clear-access-selection': 'x'
};
for (const [id, name] of Object.entries(buttonIcons)) {
    const button = document.getElementById(id);
    if (!button) continue;
    const icon = document.createElement('i');
    icon.dataset.lucide = name;
    icon.setAttribute('aria-hidden', 'true');
    button.prepend(icon);
}
window.renderMonitorIcons();
