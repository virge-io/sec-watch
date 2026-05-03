import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

const DEFAULT_REFRESH_SECONDS = 1800;
const LOCKFILE_REFRESH_DELAY_SECONDS = 2;

const NOTIFICATION_CATEGORIES = [
    ['fedora', 'fedora', 'Fedora advisories'],
    ['dep-critical', 'depCritical', 'Critical dependencies'],
    ['dep-high', 'depHigh', 'High dependencies'],
    ['dep-medium', 'depMedium', 'Medium dependencies'],
    ['dep-low', 'depLow', 'Low dependencies'],
    ['watch', 'watch', 'Public watchlist matches'],
];

function runCommandAsync(argv, callback) {
    try {
        const proc = Gio.Subprocess.new(
            argv,
            Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
        );

        proc.communicate_utf8_async(null, null, (process, result) => {
            try {
                const [, stdout, stderr] = process.communicate_utf8_finish(result);
                callback({
                    ok: process.get_successful(),
                    stdout: stdout.trim(),
                    stderr: stderr.trim(),
                });
            } catch (error) {
                callback({ok: false, stdout: '', stderr: String(error)});
            }
        });
    } catch (error) {
        callback({ok: false, stdout: '', stderr: String(error)});
    }
}

const SecurityWatchIndicator = GObject.registerClass(
class SecurityWatchIndicator extends PanelMenu.Button {
    _init(settings) {
        super._init(0.0, 'Security Watch');

        this._settings = settings;
        this._script = GLib.build_filenamev([GLib.get_home_dir(), '.local', 'bin', 'sec-watch']);
        this._label = new St.Label({
            text: 'Sec: ...',
            y_align: Clutter.ActorAlign.CENTER,
        });

        this.add_child(this._label);
        this._buildMenu();
        this._refreshing = false;
        this._lastCounts = null;
        this._suppressNextNotification = false;
        this._lockfileMonitors = [];
        this._lockfileRefreshId = null;
        this._lockfileMonitorGeneration = 0;
        this._refresh();

        this._settingsChangedId = this._settings.connect('changed', () => {
            this._resetTimer();
            this._resetLockfileMonitors();
            this._suppressNextNotification = true;
            this._refresh(true);
        });
        this._resetTimer();
        this._resetLockfileMonitors();
    }

    _buildMenu() {
        this._fedoraItem = new PopupMenu.PopupMenuItem('Fedora: ...', {
            reactive: false,
        });
        this._depCriticalItem = new PopupMenu.PopupMenuItem('Deps critical: ...', {
            reactive: false,
        });
        this._depHighItem = new PopupMenu.PopupMenuItem('Deps high: ...', {
            reactive: false,
        });
        this._depMediumItem = new PopupMenu.PopupMenuItem('Deps medium: ...', {
            reactive: false,
        });
        this._depLowItem = new PopupMenu.PopupMenuItem('Deps low: ...', {
            reactive: false,
        });
        this._depTotalItem = new PopupMenu.PopupMenuItem('Deps total: ...', {
            reactive: false,
        });
        this._watchItem = new PopupMenu.PopupMenuItem('Watch matches: ...', {
            reactive: false,
        });
        this._recentItem = new PopupMenu.PopupMenuItem('Recent changes: ...', {
            reactive: false,
        });
        this._scannerItem = new PopupMenu.PopupMenuItem('Project scanner: ...', {
            reactive: false,
        });
        this._lockfileItem = new PopupMenu.PopupMenuItem('Lockfiles watched: ...', {
            reactive: false,
        });
        this._lastScanItem = new PopupMenu.PopupMenuItem('Last scan: ...', {
            reactive: false,
        });

        const refreshItem = new PopupMenu.PopupMenuItem('Refresh');
        refreshItem.connect('activate', () => this._refresh(true));
        this._openReportItem = new PopupMenu.PopupMenuItem('Open dependency report');
        this._openReportItem.connect('activate', () => this._openDependencyReport());

        this.menu.addMenuItem(this._fedoraItem);
        this.menu.addMenuItem(this._depCriticalItem);
        this.menu.addMenuItem(this._depHighItem);
        this.menu.addMenuItem(this._depMediumItem);
        this.menu.addMenuItem(this._depLowItem);
        this.menu.addMenuItem(this._depTotalItem);
        this.menu.addMenuItem(this._watchItem);
        this.menu.addMenuItem(this._recentItem);
        this.menu.addMenuItem(this._scannerItem);
        this.menu.addMenuItem(this._lockfileItem);
        this.menu.addMenuItem(this._lastScanItem);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addMenuItem(this._openReportItem);
        this.menu.addMenuItem(refreshItem);
    }

    _refresh(force = false) {
        if (this._refreshing)
            return;

        this._refreshing = true;
        const argv = ['/usr/bin/env', ...this._commandEnvironment(force), this._script, 'argos'];

        runCommandAsync(argv, result => {
            this._refreshing = false;
            this._updateFromResult(result);
            this._resetLockfileMonitors();
        });
    }

    _commandEnvironment(force) {
        const projectsDir = this._settings.get_string('projects-dir') ||
            GLib.build_filenamev([GLib.get_home_dir(), 'Projects']);
        const interval = this._settings.get_int('scan-interval') || DEFAULT_REFRESH_SECONDS;
        const ecosystems = this._settings.get_strv('enabled-ecosystems').join(',');
        const feeds = this._settings.get_strv('enabled-public-feeds').join(',');
        const projects = this._settings.get_strv('selected-projects').join(',');
        const env = [
            `SEC_WATCH_PROJECTS_DIR=${projectsDir}`,
            `SEC_WATCH_TTL=${interval}`,
            `SEC_WATCH_ECOSYSTEMS=${ecosystems}`,
            `SEC_WATCH_PUBLIC_FEEDS=${feeds}`,
            `SEC_WATCH_PROJECTS=${projects}`,
        ];

        if (force)
            env.push('SEC_WATCH_FORCE=1');

        return env;
    }

    _resetTimer() {
        if (this._timer)
            GLib.source_remove(this._timer);

        const interval = Math.max(300, this._settings.get_int('scan-interval') || DEFAULT_REFRESH_SECONDS);
        this._timer = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            interval,
            () => {
                this._refresh();
                return GLib.SOURCE_CONTINUE;
            }
        );
    }

    _setRowText(item, text) {
        item.label.set_text(text);
        item.label.set_style(text.includes('↑') ? 'color: #ff3b30;' : '');
    }

    _countFromLine(line) {
        const match = line?.match(/:\s*(\d+)/);
        return match ? Number.parseInt(match[1], 10) : 0;
    }

    _countsFromLines(lines) {
        return {
            fedora: this._countFromLine(lines.find(line => line.startsWith('Fedora security advisories:'))),
            depCritical: this._countFromLine(lines.find(line => line.startsWith('Deps critical:'))),
            depHigh: this._countFromLine(lines.find(line => line.startsWith('Deps high:'))),
            depMedium: this._countFromLine(lines.find(line => line.startsWith('Deps medium:'))),
            depLow: this._countFromLine(lines.find(line => line.startsWith('Deps low:'))),
            watch: this._countFromLine(lines.find(line => line.startsWith('Watch matches:'))),
        };
    }

    _notifyOnCountIncreases(counts) {
        if (!this._lastCounts || this._suppressNextNotification) {
            this._lastCounts = counts;
            this._suppressNextNotification = false;
            return;
        }

        const enabled = new Set(this._settings.get_strv('notification-categories'));
        const changed = [];

        for (const [id, key, label] of NOTIFICATION_CATEGORIES) {
            if (!enabled.has(id))
                continue;

            const previous = this._lastCounts[key] ?? 0;
            const current = counts[key] ?? 0;
            if (current > previous)
                changed.push(`${label}: ${previous} -> ${current}`);
        }

        this._lastCounts = counts;

        if (changed.length > 0)
            Main.notify('Security Watch found new vulnerabilities', changed.join('\n'));
    }

    _clearLockfileMonitors() {
        for (const monitor of this._lockfileMonitors)
            monitor.cancel();
        this._lockfileMonitors = [];

        if (this._lockfileRefreshId) {
            GLib.source_remove(this._lockfileRefreshId);
            this._lockfileRefreshId = null;
        }
    }

    _resetLockfileMonitors() {
        const generation = ++this._lockfileMonitorGeneration;
        this._clearLockfileMonitors();

        if (!this._settings.get_boolean('watch-lockfiles')) {
            this._lockfileItem.label.set_text('Lockfiles watched: off');
            return;
        }

        const argv = ['/usr/bin/env', ...this._commandEnvironment(false), this._script, 'lockfiles'];
        runCommandAsync(argv, result => {
            if (generation !== this._lockfileMonitorGeneration)
                return;

            if (!result.ok && !result.stdout) {
                this._lockfileItem.label.set_text('Lockfiles watched: unavailable');
                return;
            }

            const paths = result.stdout.split('\n').map(path => path.trim()).filter(Boolean);
            for (const path of paths) {
                try {
                    const monitor = Gio.File.new_for_path(path).monitor_file(Gio.FileMonitorFlags.NONE, null);
                    monitor.connect('changed', (_monitor, _file, _otherFile, eventType) => {
                        this._handleLockfileChanged(eventType);
                    });
                    this._lockfileMonitors.push(monitor);
                } catch {
                    // Ignore files that disappear between listing and monitor setup.
                }
            }

            this._lockfileItem.label.set_text(`Lockfiles watched: ${this._lockfileMonitors.length}`);
        });
    }

    _handleLockfileChanged(eventType) {
        const relevantEvents = [
            Gio.FileMonitorEvent.CHANGED,
            Gio.FileMonitorEvent.CHANGES_DONE_HINT,
            Gio.FileMonitorEvent.CREATED,
            Gio.FileMonitorEvent.DELETED,
            Gio.FileMonitorEvent.MOVED_IN,
            Gio.FileMonitorEvent.MOVED_OUT,
            Gio.FileMonitorEvent.RENAMED,
        ];

        if (!relevantEvents.includes(eventType) || this._lockfileRefreshId)
            return;

        this._lockfileRefreshId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            LOCKFILE_REFRESH_DELAY_SECONDS,
            () => {
                this._lockfileRefreshId = null;
                this._refresh(true);
                return GLib.SOURCE_REMOVE;
            }
        );
    }

    _updateFromResult(result) {
        if (!result.ok && !result.stdout) {
            this._label.set_text('Sec: err');
            this._fedoraItem.label.set_text('Fedora: unavailable');
            this._setRowText(this._depCriticalItem, 'Deps critical: unavailable');
            this._setRowText(this._depHighItem, 'Deps high: unavailable');
            this._depMediumItem.label.set_text('Deps medium: unavailable');
            this._depLowItem.label.set_text('Deps low: unavailable');
            this._depTotalItem.label.set_text('Deps total: unavailable');
            this._watchItem.label.set_text('Watch matches: unavailable');
            this._recentItem.label.set_text('Recent changes: unavailable');
            this._scannerItem.label.set_text('Project scanner: error');
            this._lastScanItem.label.set_text(result.stderr || 'Could not run sec-watch');
            this._label.set_style('color: #ff3b30;');
            return;
        }

        const lines = result.stdout.split('\n').map(line => line.trim()).filter(Boolean);
        this._notifyOnCountIncreases(this._countsFromLines(lines));
        const titleLine = lines[0] ?? '';
        const title = titleLine.split('|')[0]?.trim() || 'Sec: ...';
        const colorMatch = titleLine.match(/\|\s*color=([^ ]+)/);
        this._label.set_text(title);
        this._label.set_style(colorMatch ? `color: ${colorMatch[1]};` : '');

        const fedoraLine = lines.find(line => line.startsWith('Fedora security advisories:')) ?? '';
        const fedora = fedoraLine ? fedoraLine.replace('Fedora security advisories:', 'Fedora:') : 'Fedora: ...';
        const depCritical = lines.find(line => line.startsWith('Deps critical:')) ?? 'Deps critical: ...';
        const depHigh = lines.find(line => line.startsWith('Deps high:')) ?? 'Deps high: ...';
        const depMedium = lines.find(line => line.startsWith('Deps medium:')) ?? 'Deps medium: ...';
        const depLow = lines.find(line => line.startsWith('Deps low:')) ?? 'Deps low: ...';
        const depTotal = lines.find(line => line.startsWith('Deps total:')) ?? 'Deps total: ...';
        const watch = lines.find(line => line.startsWith('Watch matches:')) ?? 'Watch matches: ...';
        const recent = lines.find(line => line.startsWith('Recent changes:')) ?? 'Recent changes: ...';
        const scanner = lines.find(line => line.startsWith('Project scanner:')) ?? 'Project scanner: ...';
        const report = lines.find(line => line.startsWith('Dependency report:')) ?? '';
        const lastScan = lines.find(line => line.startsWith('Last scan:')) ?? 'Last scan: ...';

        this._fedoraItem.label.set_text(fedora);
        this._setRowText(this._depCriticalItem, depCritical);
        this._setRowText(this._depHighItem, depHigh);
        this._depMediumItem.label.set_text(depMedium);
        this._depLowItem.label.set_text(depLow);
        this._depTotalItem.label.set_text(depTotal);
        this._watchItem.label.set_text(watch);
        this._recentItem.label.set_text(recent);
        this._scannerItem.label.set_text(scanner);
        this._reportPath = report.replace('Dependency report:', '').trim();
        this._lastScanItem.label.set_text(lastScan);
    }

    _openDependencyReport() {
        if (!this._reportPath)
            return;

        runCommandAsync(['xdg-open', this._reportPath], () => {});
    }

    destroy() {
        if (this._timer) {
            GLib.source_remove(this._timer);
            this._timer = null;
        }

        if (this._settingsChangedId) {
            this._settings.disconnect(this._settingsChangedId);
            this._settingsChangedId = null;
        }

        this._lockfileMonitorGeneration++;
        this._clearLockfileMonitors();

        super.destroy();
    }
});

export default class SecurityWatchExtension extends Extension {
    enable() {
        this._settings = this.getSettings();
        this._indicator = new SecurityWatchIndicator(this._settings);
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
        this._settings = null;
    }
}
