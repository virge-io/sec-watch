import Adw from 'gi://Adw';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk';

import {ExtensionPreferences} from 'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js';

const ECOSYSTEMS = [
    ['npm', 'NPM package-lock'],
    ['yarn', 'Yarn'],
    ['pnpm', 'PNPM'],
    ['pip', 'Python requirements'],
    ['poetry', 'Poetry'],
    ['uv', 'uv'],
    ['python-pkg', 'Python environments'],
];

const PUBLIC_FEEDS = [
    ['manual', 'Manual CVE watchlist', 'Configured in ~/.config/sec-watch/watch.json'],
    ['cisa-kev', 'CISA KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'],
    ['nvd-recent', 'NVD Recent', 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz'],
];

const NOTIFICATION_CATEGORIES = [
    ['fedora', 'Fedora advisories'],
    ['dep-critical', 'Critical dependencies'],
    ['dep-high', 'High dependencies'],
    ['dep-medium', 'Medium dependencies'],
    ['dep-low', 'Low dependencies'],
    ['watch', 'Public watchlist matches'],
];

function defaultProjectsDir() {
    return GLib.build_filenamev([GLib.get_home_dir(), 'Projects']);
}

function getProjectsDir(settings) {
    return settings.get_string('projects-dir') || defaultProjectsDir();
}

function getProjectNames(settings) {
    const root = Gio.File.new_for_path(getProjectsDir(settings));
    const projects = [];

    try {
        const children = root.enumerate_children(
            'standard::name,standard::type',
            Gio.FileQueryInfoFlags.NONE,
            null
        );

        let info;
        while ((info = children.next_file(null)) !== null) {
            const name = info.get_name();
            if (info.get_file_type() === Gio.FileType.DIRECTORY && !name.startsWith('.'))
                projects.push(name);
        }
    } catch {
        return [];
    }

    return projects.sort((a, b) => a.localeCompare(b));
}

function hasValue(values, value) {
    return values.includes(value);
}

function setValue(values, value, enabled) {
    const next = values.filter(item => item !== value);
    if (enabled)
        next.push(value);
    return next.sort((a, b) => a.localeCompare(b));
}

export default class SecWatchPrefs extends ExtensionPreferences {
    fillPreferencesWindow(window) {
        const settings = this.getSettings();

        window.set_default_size(640, 760);

        const page = new Adw.PreferencesPage({
            title: 'Security Watch',
            icon_name: 'security-high-symbolic',
        });

        page.add(this._buildScanGroup(settings));
        page.add(this._buildNotificationGroup(settings));
        page.add(this._buildPublicFeedGroup(settings));
        page.add(this._buildEcosystemGroup(settings));
        page.add(this._buildProjectGroup(settings));

        window.add(page);
    }

    _buildScanGroup(settings) {
        const group = new Adw.PreferencesGroup({
            title: 'Scan',
        });

        const dirRow = new Adw.ActionRow({
            title: 'Projects directory',
            subtitle: 'Root folder containing your local repositories',
        });

        const dirEntry = new Gtk.Entry({
            text: getProjectsDir(settings),
            hexpand: true,
            width_chars: 24,
        });
        dirEntry.connect('changed', entry => {
            settings.set_string('projects-dir', entry.text.trim());
        });

        const chooseButton = new Gtk.Button({
            label: 'Choose',
            valign: Gtk.Align.CENTER,
        });
        chooseButton.connect('clicked', button => {
            const chooser = new Gtk.FileChooserNative({
                title: 'Select Projects Directory',
                action: Gtk.FileChooserAction.SELECT_FOLDER,
                modal: true,
                transient_for: button.get_root(),
            });
            chooser.set_current_folder(Gio.File.new_for_path(getProjectsDir(settings)));
            chooser.connect('response', (dialog, response) => {
                if (response === Gtk.ResponseType.ACCEPT) {
                    const file = dialog.get_file();
                    if (file)
                        settings.set_string('projects-dir', file.get_path());
                    dirEntry.text = getProjectsDir(settings);
                }
            });
            chooser.show();
        });

        dirRow.add_suffix(dirEntry);
        dirRow.add_suffix(chooseButton);
        group.add(dirRow);

        const intervalRow = new Adw.SpinRow({
            title: 'Scan interval',
            subtitle: 'How often the panel refresh triggers a real scan',
            adjustment: new Gtk.Adjustment({
                lower: 5,
                upper: 1440,
                step_increment: 5,
                page_increment: 30,
                value: Math.round(settings.get_int('scan-interval') / 60),
            }),
        });
        intervalRow.add_suffix(new Gtk.Label({
            label: 'min',
            valign: Gtk.Align.CENTER,
            css_classes: ['dim-label'],
        }));
        intervalRow.connect('notify::value', row => {
            settings.set_int('scan-interval', Math.round(row.get_value()) * 60);
        });
        group.add(intervalRow);

        const lockfileRow = new Adw.SwitchRow({
            title: 'Rescan on lockfile changes',
            subtitle: 'Watches dependency manifests and lockfiles for selected projects',
        });
        settings.bind(
            'watch-lockfiles',
            lockfileRow,
            'active',
            Gio.SettingsBindFlags.DEFAULT
        );
        group.add(lockfileRow);

        return group;
    }

    _buildNotificationGroup(settings) {
        const group = new Adw.PreferencesGroup({
            title: 'Notifications',
            description: 'Notify when a scan sees a category count increase.',
        });

        for (const [id, title] of NOTIFICATION_CATEGORIES) {
            const row = new Adw.SwitchRow({title});
            row.active = hasValue(settings.get_strv('notification-categories'), id);
            row.connect('notify::active', switchRow => {
                settings.set_strv(
                    'notification-categories',
                    setValue(settings.get_strv('notification-categories'), id, switchRow.active)
                );
            });
            group.add(row);
        }

        return group;
    }

    _buildPublicFeedGroup(settings) {
        const group = new Adw.PreferencesGroup({
            title: 'Public Vulnerability Lists',
            description: 'These feeds supplement Fedora advisory metadata and project dependency scans.',
        });

        for (const [id, title, subtitle] of PUBLIC_FEEDS) {
            const row = new Adw.SwitchRow({title, subtitle});
            row.active = hasValue(settings.get_strv('enabled-public-feeds'), id);
            row.connect('notify::active', switchRow => {
                settings.set_strv(
                    'enabled-public-feeds',
                    setValue(settings.get_strv('enabled-public-feeds'), id, switchRow.active)
                );
            });
            group.add(row);
        }

        return group;
    }

    _buildEcosystemGroup(settings) {
        const group = new Adw.PreferencesGroup({
            title: 'Dependency Types',
        });

        for (const [id, title] of ECOSYSTEMS) {
            const row = new Adw.SwitchRow({title});
            row.active = hasValue(settings.get_strv('enabled-ecosystems'), id);
            row.connect('notify::active', switchRow => {
                settings.set_strv(
                    'enabled-ecosystems',
                    setValue(settings.get_strv('enabled-ecosystems'), id, switchRow.active)
                );
            });
            group.add(row);
        }

        return group;
    }

    _buildProjectGroup(settings) {
        const group = new Adw.PreferencesGroup({
            title: 'Projects',
            description: 'Empty selection means every project in the root directory is scanned.',
        });

        const projects = getProjectNames(settings);
        const allRow = new Adw.SwitchRow({
            title: 'Scan all projects',
        });

        const projectRows = [];
        const updateRows = () => {
            const selected = settings.get_strv('selected-projects');
            const scanAll = selected.length === 0;
            allRow.active = scanAll;

            for (const [name, row] of projectRows) {
                row.sensitive = !scanAll;
                row.active = scanAll || hasValue(selected, name);
            }
        };

        allRow.connect('notify::active', row => {
            if (row.active) {
                settings.set_strv('selected-projects', []);
            } else if (settings.get_strv('selected-projects').length === 0) {
                settings.set_strv('selected-projects', projects);
            }
            updateRows();
        });
        group.add(allRow);

        if (projects.length === 0) {
            group.add(new Adw.ActionRow({
                title: 'No project folders found',
                subtitle: getProjectsDir(settings),
            }));
            return group;
        }

        for (const name of projects) {
            const row = new Adw.SwitchRow({title: name});
            row.connect('notify::active', switchRow => {
                if (settings.get_strv('selected-projects').length === 0)
                    return;
                settings.set_strv(
                    'selected-projects',
                    setValue(settings.get_strv('selected-projects'), name, switchRow.active)
                );
            });
            projectRows.push([name, row]);
            group.add(row);
        }

        settings.connect('changed::selected-projects', updateRows);
        updateRows();

        return group;
    }
}
