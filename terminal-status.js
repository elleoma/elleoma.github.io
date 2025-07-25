/**
 * Terminal Status Display - Retro VHS Style
 * Adapted from Dave Eddy's terminal emulator for elleoma@logs
 */

const TYPING_SPEED = 80;
const INITIAL_DELAY = 1500;
const SUBSEQUENT_DELAY = 8000;
const CURSOR_BLINK_START = 1;
const CURSOR_BLINK_END = 2;

// Define your commands and their outputs
const COMMANDS = [
    {
        cmd: 'curl forsen-cock.dedyn.io/status',
        lines: [
            'Connecting to status endpoint...',
            '',
            '<span class="status-active">[--------██-------██-----]</span> - <span class="service-name">main website</span> <span class="service-url">(forsen-cock.dedyn.io)</span>',
            '<span class="status-active">[-█------██--------------]</span> - <span class="service-name">gitea instance</span> <span class="service-url">(git.forsen-cock.dedyn.io)</span>',
            '<span class="status-active">[-█------██--------------]</span> - <span class="service-name">vaultwarden</span> <span class="service-url">(vault.forsen-cock.dedyn.io)</span>',
            '<span class="status-loading">[------------------------]</span> - <span class="service-name">matrix server</span> <span class="service-url">(@forsen-cock.dedyn.io)</span>',
            '<span class="status-active">[--██----██--------------]</span> - <span class="service-name">status page</span> <span class="service-url">(status.forsen-cock.dedyn.io)</span>',
            ''
        ]
    },
    {
        cmd: 'systemctl status docker',
        lines: [
            '● docker.service - Docker Application Container Engine',
            '   Loaded: loaded (/lib/systemd/system/docker.service; enabled)',
            '   Active: <span class="status-active">active (running)</span> since Mon 2025-07-25 14:30:22 UTC',
            '     Docs: https://docs.docker.com',
            ' Main PID: 1024 (dockerd)',
            '    Tasks: 42',
            '   Memory: 156.2M',
            ''
        ]
    },
    {
        cmd: 'docker ps --format "table {{.Names}}\\t{{.Status}}"',
        lines: [
            'NAMES                    STATUS',
            'vaultwarden             <span class="status-active">Up 2 hours</span>',
            'gitea                   <span class="status-active">Up 2 hours</span>', 
            'nginx-proxy-manager     <span class="status-active">Up 2 hours</span>',
            'matrix-tuwunel          <span class="status-loading">Restarting (1) 3s ago</span>',
            'gatus                   <span class="status-active">Up 2 hours</span>',
            ''
        ]
    },
    {
        cmd: 'htop -n 1 | head -5',
        lines: [
            'top - 16:45:32 up  2:15,  1 user,  load average: 0.08, 0.12, 0.09',
            'Tasks:  42 total,   1 running,  41 sleeping,   0 stopped,   0 zombie',
            '%Cpu(s):  2.1 us,  1.2 sy,  0.0 ni, 96.5 id,  0.2 wa,  0.0 hi,  0.0 si',
            'MiB Mem :   3906.2 total,    852.4 free,   1247.8 used,   1806.0 buff/cache',
            ''
        ]
    }
];

let terminal;

function runCommand(i, cb) {
    let o = COMMANDS[i];
    let lines = o.lines;
    let command = o.cmd.split('');
    let output = lines.map((line) => line + '\n');
    
    let prompt = 'elleoma@logs:~$ ';
    let items = [].concat(
        CURSOR_BLINK_END,
        command,
        ['\n'],
        output,
        prompt,
        CURSOR_BLINK_START,
    );

    // Clear terminal and show initial prompt
    blinkCursorStart();
    terminal.innerHTML = prompt;

    // Simulate typing the command
    let idx = 0;
    function type() {
        if (idx === items.length) {
            cb();
            return;
        }
        
        let c = items[idx];
        idx++;
        
        switch (c) {
            case CURSOR_BLINK_START:
                blinkCursorStart();
                break;
            case CURSOR_BLINK_END:
                blinkCursorEnd();
                break;
            default:
                // Handle special case for adding content after cursor
                if (terminal.classList.contains('no-animation')) {
                    terminal.innerHTML += c;
                } else {
                    // Remove cursor, add content, cursor will be re-added by CSS
                    let content = terminal.innerHTML;
                    terminal.innerHTML = content + c;
                }
                break;
        }
        setTimeout(type, TYPING_SPEED + Math.random() * 40);
    }
    type();
}

function blinkCursorStart() {
    if (terminal) {
        terminal.classList.remove('no-animation');
    }
}

function blinkCursorEnd() {
    if (terminal) {
        terminal.classList.add('no-animation');
    }
}

function main() {
    terminal = document.querySelector('#main-terminal .terminal-body') || 
               document.getElementById('main-terminal');
    
    if (!terminal) {
        console.warn('Terminal element not found');
        return;
    }
    
    terminal.innerHTML = 'elleoma@logs:~$ ';
    let i = 0;
    let max = COMMANDS.length;
    let delay = INITIAL_DELAY;

    function loop() {
        setTimeout(function () {
            delay = SUBSEQUENT_DELAY;
            runCommand(i, loop);
            i = (i + 1) % max;
        }, delay);
    }
    
    loop();
}

// Start when DOM is loaded
document.addEventListener('DOMContentLoaded', main);
